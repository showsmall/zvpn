package compression

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sync"

	"github.com/pierrec/lz4/v4"
)

// CompressionType represents compression type
type CompressionType string

const (
	CompressionNone CompressionType = "none"
	CompressionLZ4  CompressionType = "lz4"
	CompressionGzip CompressionType = "gzip"
)

// Compressor interface for compressing/decompressing data
type Compressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
}

// LZ4Compressor implements LZ4 compression
type LZ4Compressor struct {
	pool *sync.Pool
}

// NewLZ4Compressor creates a new LZ4 compressor
func NewLZ4Compressor() *LZ4Compressor {
	return &LZ4Compressor{
		pool: &sync.Pool{
			New: func() interface{} { return &bytes.Buffer{} },
		},
	}
}

func (c *LZ4Compressor) Compress(data []byte) ([]byte, error) {
	buf := c.pool.Get().(*bytes.Buffer)
	defer c.pool.Put(buf)
	buf.Reset()
	writer := lz4.NewWriter(buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

func (c *LZ4Compressor) Decompress(data []byte) ([]byte, error) {
	reader := lz4.NewReader(bytes.NewReader(data))
	buf := c.pool.Get().(*bytes.Buffer)
	defer c.pool.Put(buf)
	buf.Reset()
	if _, err := io.Copy(buf, reader); err != nil {
		return nil, err
	}
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// GzipCompressor implements Gzip compression
type GzipCompressor struct {
	pool *sync.Pool
}

// NewGzipCompressor creates a new Gzip compressor
func NewGzipCompressor() *GzipCompressor {
	return &GzipCompressor{
		pool: &sync.Pool{
			New: func() interface{} { return &bytes.Buffer{} },
		},
	}
}

func (c *GzipCompressor) Compress(data []byte) ([]byte, error) {
	buf := c.pool.Get().(*bytes.Buffer)
	defer c.pool.Put(buf)
	buf.Reset()
	writer := gzip.NewWriter(buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

func (c *GzipCompressor) Decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	buf := c.pool.Get().(*bytes.Buffer)
	defer c.pool.Put(buf)
	buf.Reset()
	if _, err := io.Copy(buf, reader); err != nil {
		return nil, err
	}
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// CompressionManager manages compression with multiple backends
type CompressionManager struct {
	compressors map[CompressionType]Compressor
	defaultType CompressionType
}

// NewCompressionManager creates a new compression manager
func NewCompressionManager(defaultType CompressionType) *CompressionManager {
	cm := &CompressionManager{
		compressors: make(map[CompressionType]Compressor),
		defaultType: defaultType,
	}
	if defaultType == CompressionLZ4 || defaultType == "" {
		cm.compressors[CompressionLZ4] = NewLZ4Compressor()
	}
	if defaultType == CompressionGzip || defaultType == "" {
		cm.compressors[CompressionGzip] = NewGzipCompressor()
	}
	return cm
}

// Compress compresses data
func (cm *CompressionManager) Compress(data []byte, compType CompressionType) ([]byte, error) {
	if compType == CompressionNone || compType == "" {
		return data, nil
	}
	compressor, ok := cm.compressors[compType]
	if !ok {
		return nil, fmt.Errorf("unsupported compression type: %s", compType)
	}
	return compressor.Compress(data)
}

// Decompress decompresses data; returns original data on error
func (cm *CompressionManager) Decompress(data []byte, compType CompressionType) ([]byte, error) {
	if compType == CompressionNone || compType == "" {
		return data, nil
	}
	compressor, ok := cm.compressors[compType]
	if !ok {
		return data, nil
	}
	decompressed, err := compressor.Decompress(data)
	if err != nil {
		return data, nil
	}
	return decompressed, nil
}

// GetDefaultType returns the default compression type
func (cm *CompressionManager) GetDefaultType() CompressionType {
	return cm.defaultType
}
