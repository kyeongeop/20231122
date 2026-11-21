package main

import (
	"archive/tar"
	"flag"
	"fmt"
	"os"
	"time"
)

type entry struct {
	name    string
	mode    int64
	uid     int
	gid     int
	size    int64
	typeflg byte
}

// The fixture intentionally exercises every audit rule plus large files
// used to trigger the memory-budget degradation path.
var entries = []entry{
	{"etc/", 0o755, 0, 0, 0, tar.TypeDir},
	{"etc/passwd", 0o644, 0, 0, 128, tar.TypeReg},
	{"etc/shadow", 0o644, 0, 0, 96, tar.TypeReg},
	{"usr/", 0o755, 0, 0, 0, tar.TypeDir},
	{"usr/bin/", 0o755, 0, 0, 0, tar.TypeDir},
	{"usr/bin/su", 0o4755, 0, 0, 4096, tar.TypeReg},
	{"usr/bin/sg", 0o2755, 0, 0, 2048, tar.TypeReg},
	{"tmp/", 0o777, 0, 0, 0, tar.TypeDir},
	{"var/", 0o755, 0, 0, 0, tar.TypeDir},
	{"var/log/", 0o777, 0, 0, 0, tar.TypeDir},
	{"home/", 0o755, 1000, 1000, 0, tar.TypeDir},
	{"home/user/", 0o755, 1000, 1000, 0, tar.TypeDir},
	{"home/user/notes.txt", 0o666, 1000, 1000, 64, tar.TypeReg},
	{"usr/bin/rootw", 0o766, 0, 0, 512, tar.TypeReg},
	{"opt/", 0o755, 0, 0, 0, tar.TypeDir},
	{"opt/blob.bin", 0o644, 0, 0, 1 << 20, tar.TypeReg},
	{"opt/blob2.bin", 0o644, 0, 0, 1 << 20, tar.TypeReg},
	{"opt/blob3.bin", 0o644, 0, 0, 1 << 20, tar.TypeReg},
	{"etc/hostname", 0o644, 0, 0, 16, tar.TypeReg},
	{"sbin/", 0o755, 0, 0, 0, tar.TypeDir},
	{"sbin/init", 0o755, 0, 0, 8192, tar.TypeReg},
}

func main() {
	out := flag.String("out", "artifacts/image.tar", "output tar path")
	flag.Parse()

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	mtime := time.Unix(1700000000, 0)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Uid:      e.uid,
			Gid:      e.gid,
			Size:     e.size,
			Typeflag: e.typeflg,
			ModTime:  mtime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if e.typeflg == tar.TypeReg && e.size > 0 {
			buf := make([]byte, e.size)
			for i := range buf {
				buf[i] = byte(i % 251)
			}
			if _, err := tw.Write(buf); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
	if err := tw.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d entries)\n", *out, len(entries))
}
