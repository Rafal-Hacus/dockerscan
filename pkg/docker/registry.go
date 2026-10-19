package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	goruntime "runtime"
	"strings"

	"github.com/cr0hn/dockerscan/v2/pkg/auth"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Registry mode reads images straight from their registry instead of through
// a Docker daemon. It is used when no daemon is reachable, e.g. when
// dockerscan itself runs inside a container platform. Image metadata and
// layers are fetched with go-containerregistry; layers are cached on disk so
// the scanners, which each walk the image files, download them only once.
// Container inspection is not available in this mode.

// UseRegistry switches the client to registry mode
func (c *Client) UseRegistry() error {
	cacheDir, err := os.MkdirTemp("", "dockerscan-layers-*")
	if err != nil {
		return fmt.Errorf("failed to create layer cache dir: %w", err)
	}

	c.registryMode = true
	c.layerCacheDir = cacheDir
	c.remoteImages = make(map[string]*remoteImage)
	return nil
}

// RegistryMode reports whether the client reads images from the registry
func (c *Client) RegistryMode() bool {
	return c.registryMode
}

// remoteImage is an image fetched from a registry
type remoteImage struct {
	ref    name.Reference
	digest v1.Hash
	image  v1.Image
}

// pullRemote fetches the image manifest and config, for the platform
// dockerscan runs on, and keeps it for later reads. Layers are downloaded
// lazily, on first use.
func (c *Client) pullRemote(ctx context.Context, imageName string, registryAuth *auth.RegistryAuth) error {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return fmt.Errorf("invalid image reference %s: %w", imageName, err)
	}

	authenticator := authn.Anonymous
	if registryAuth != nil && (registryAuth.Username != "" || registryAuth.IdentityToken != "") {
		authenticator = authn.FromConfig(authn.AuthConfig{
			Username:      registryAuth.Username,
			Password:      registryAuth.Password,
			IdentityToken: registryAuth.IdentityToken,
		})
	}

	desc, err := remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuth(authenticator),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: goruntime.GOARCH}),
	)
	if err != nil {
		return fmt.Errorf("failed to pull image %s from registry: %w", imageName, err)
	}

	img, err := desc.Image()
	if err != nil {
		return fmt.Errorf("failed to read image %s: %w", imageName, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("failed to read image digest: %w", err)
	}

	c.remoteImages[imageName] = &remoteImage{
		ref:    ref,
		digest: digest,
		image:  cache.Image(img, cache.NewFilesystemCache(c.layerCacheDir)),
	}
	return nil
}

func (c *Client) getRemote(imageName string) (*remoteImage, error) {
	ri, ok := c.remoteImages[imageName]
	if !ok {
		return nil, fmt.Errorf("image %s has not been pulled", imageName)
	}
	return ri, nil
}

// inspectRemote builds ImageInfo from the image config and manifest
func (c *Client) inspectRemote(imageName string) (*ImageInfo, error) {
	ri, err := c.getRemote(imageName)
	if err != nil {
		return nil, err
	}

	cfg, err := ri.image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}
	manifest, err := ri.image.Manifest()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}
	configName, err := ri.image.ConfigName()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	var size int64
	for _, layer := range manifest.Layers {
		size += layer.Size
	}

	layers := make([]string, len(cfg.RootFS.DiffIDs))
	for i, diffID := range cfg.RootFS.DiffIDs {
		layers[i] = diffID.String()
	}

	info := &ImageInfo{
		ID:           configName.String(),
		RepoTags:     []string{imageName},
		RepoDigests:  []string{ri.ref.Context().Name() + "@" + ri.digest.String()},
		Created:      cfg.Created.Time,
		Size:         size,
		Architecture: cfg.Architecture,
		OS:           cfg.OS,
		Author:       cfg.Author,
		User:         cfg.Config.User,
		Cmd:          cfg.Config.Cmd,
		Entrypoint:   cfg.Config.Entrypoint,
		WorkingDir:   cfg.Config.WorkingDir,
		Labels:       cfg.Config.Labels,
		Env:          make(map[string]string),
		LayerCount:   len(layers),
		RootFS: RootFSInfo{
			Type:   cfg.RootFS.Type,
			Layers: layers,
		},
	}

	for _, env := range cfg.Config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			info.Env[parts[0]] = parts[1]
		}
	}
	for port := range cfg.Config.ExposedPorts {
		info.ExposedPorts = append(info.ExposedPorts, port)
	}
	for vol := range cfg.Config.Volumes {
		info.Volumes = append(info.Volumes, vol)
	}
	if hc := cfg.Config.Healthcheck; hc != nil {
		info.Healthcheck = &HealthcheckConfig{
			Test:        hc.Test,
			Interval:    hc.Interval,
			Timeout:     hc.Timeout,
			StartPeriod: hc.StartPeriod,
			Retries:     hc.Retries,
		}
	}

	return info, nil
}

// historyRemote returns the build history newest first, like the Docker API
func (c *Client) historyRemote(imageName string) ([]HistoryEntry, error) {
	ri, err := c.getRemote(imageName)
	if err != nil {
		return nil, err
	}

	cfg, err := ri.image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to get image history: %w", err)
	}
	manifest, err := ri.image.Manifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get image history: %w", err)
	}

	// Non-empty history steps map, in order, to the manifest layers
	entries := make([]HistoryEntry, 0, len(cfg.History))
	layerIdx := 0
	for _, h := range cfg.History {
		entry := HistoryEntry{
			Created:    h.Created.Time,
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			EmptyLayer: h.EmptyLayer,
		}
		if !h.EmptyLayer && layerIdx < len(manifest.Layers) {
			entry.Size = manifest.Layers[layerIdx].Size
			layerIdx++
		}
		entries = append(entries, entry)
	}

	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries, nil
}

// scanRemoteFiles walks every file of every layer, base layer first
func (c *Client) scanRemoteFiles(imageName string, callback func(FileInfo, io.Reader) error) error {
	ri, err := c.getRemote(imageName)
	if err != nil {
		return err
	}

	layers, err := ri.image.Layers()
	if err != nil {
		return fmt.Errorf("failed to read image layers: %w", err)
	}

	for _, layer := range layers {
		digest, _ := layer.Digest()
		if err := processLayerReader(layer, callback); err != nil {
			return fmt.Errorf("failed to process layer %s: %w", digest, err)
		}
	}
	return nil
}

func processLayerReader(layer v1.Layer, callback func(FileInfo, io.Reader) error) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return err
	}
	defer rc.Close()
	return processTar(rc, callback)
}
