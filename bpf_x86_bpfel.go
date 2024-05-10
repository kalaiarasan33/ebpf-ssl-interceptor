// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfSslDataEventT struct {
	Pid        uint32
	Len        uint32
	IsOutgoing int8
	Buf        [80]uint8
	_          [3]byte
}

type bpfSslReadData struct {
	Len uint32
	_   [4]byte
	Buf uint64
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	UprobeLibsslRead    *ebpf.ProgramSpec `ebpf:"uprobe_libssl_read"`
	UprobeLibsslWrite   *ebpf.ProgramSpec `ebpf:"uprobe_libssl_write"`
	UretprobeLibsslRead *ebpf.ProgramSpec `ebpf:"uretprobe_libssl_read"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	SslDataEventMap *ebpf.MapSpec `ebpf:"ssl_data_event_map"`
	SslReadDataMap  *ebpf.MapSpec `ebpf:"ssl_read_data_map"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	SslDataEventMap *ebpf.Map `ebpf:"ssl_data_event_map"`
	SslReadDataMap  *ebpf.Map `ebpf:"ssl_read_data_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.SslDataEventMap,
		m.SslReadDataMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	UprobeLibsslRead    *ebpf.Program `ebpf:"uprobe_libssl_read"`
	UprobeLibsslWrite   *ebpf.Program `ebpf:"uprobe_libssl_write"`
	UretprobeLibsslRead *ebpf.Program `ebpf:"uretprobe_libssl_read"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.UprobeLibsslRead,
		p.UprobeLibsslWrite,
		p.UretprobeLibsslRead,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_x86_bpfel.o
var _BpfBytes []byte
