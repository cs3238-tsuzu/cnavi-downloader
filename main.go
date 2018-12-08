package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/grafov/m3u8"
)

const MetaPlaylistURLBase = "https://hls-vod-auth.stream.co.jp/hls-vod-auth/waseda-wse/meta.m3u8?tk="

func get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36")

	return http.DefaultClient.Do(req)
}

func getMetaPlaylist(url string) (string, error) {
	resp, err := get(url)

	if err != nil {
		return "", err
	}

	p, listType, err := m3u8.DecodeFrom(resp.Body, false)

	switch listType {
	case m3u8.MEDIA:
		playlist := p.(*m3u8.MasterPlaylist)

		return playlist.Variants[0].URI, nil
	case m3u8.MASTER:
		playlist := p.(*m3u8.MasterPlaylist)

		return playlist.Variants[0].URI, nil
	}

	return "", errors.New("invalid playlist type")
}

type movieSegment struct {
	Encryption bool
	KeyURI     string
	URL        string
	SegmentNo  uint64
	IV         []byte
	Response   *http.Response
}

type DecryptingDecoder struct {
	base      io.Reader
	key       []byte
	iv        []byte
	blockMode cipher.BlockMode
}

func newDecryptingDecoderForM3U8(from io.Reader, keyURL string, iv []byte) (*DecryptingDecoder, error) {
	resp, err := get(keyURL)

	if err != nil {
		return nil, err
	}

	key, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)

	return &DecryptingDecoder{
		base:      from,
		key:       key,
		iv:        iv,
		blockMode: blockMode,
	}, nil
}

func (dd *DecryptingDecoder) Read(b []byte) (int, error) {
	buf := make([]byte, len(b)/dd.blockMode.BlockSize()*dd.blockMode.BlockSize())
	n, err := io.ReadFull(dd.base, buf)

	if err != nil {
		return 0, err
	}

	buf = buf[:n]

	dd.blockMode.CryptBlocks(b, buf)

	return n, nil
}

func downloadMovie(url string) (r io.ReadCloser, err error) {
	resp, err := get(url)

	if err != nil {
		return nil, err
	}

	p, listType, err := m3u8.DecodeFrom(resp.Body, false)

	if listType != m3u8.MEDIA {
		return nil, errors.New("invalid playlist type")
	}

	playlist := p.(*m3u8.MediaPlaylist)

	key := playlist.Key

	segments := make([]*movieSegment, 0, int(playlist.Count()))

	defer func() {
		if err != nil {
			for i := range segments {
				segments[i].Response.Body.Close()
			}
		}
	}()

	offset := playlist.SeqNo

	for i := uint(0); i < playlist.Count(); i++ {
		seg := playlist.Segments[i]

		if seg.Key != nil {
			key = seg.Key
		}

		mseg := &movieSegment{}

		mseg.Encryption = strings.ToUpper(key.Method) != "NONE"
		mseg.URL = seg.URI
		mseg.SegmentNo = offset + uint64(i)

		if mseg.Encryption {
			mseg.KeyURI = key.URI
			if iv, err := hex.DecodeString(key.IV); err == nil || len(iv) == 0 {
				mseg.IV = iv
			}

			if mseg.IV == nil || len(mseg.IV) == 0 {
				var iv [16]byte
				binary.BigEndian.PutUint64(iv[8:], mseg.SegmentNo)
				mseg.IV = iv[:]
			}
		}

		segments = append(segments, mseg)
	}

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		for i := range segments {
			segments[i].Response, err = get(segments[i].URL)

			if err != nil {
				segments[i].Response.Body.Close()

				pw.CloseWithError(err)
				return
			}

			decoder, err := newDecryptingDecoderForM3U8(segments[i].Response.Body, segments[i].KeyURI, segments[i].IV)

			if err != nil {
				segments[i].Response.Body.Close()

				pw.CloseWithError(err)
				return
			}

			io.Copy(pw, decoder)
			segments[i].Response.Body.Close()
		}
	}()

	return pr, nil
}

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		log.Fatal("$PORT must be set")
	}

	mux := http.NewServeMux()

	handler := func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			rw.Write([]byte("Method not implemented"))

			return
		}

		authToken2 := req.FormValue("auth_token2")

		master, err := getMetaPlaylist(MetaPlaylistURLBase + authToken2)

		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte(err.Error()))

			return
		}

		reader, err := downloadMovie(master)

		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte(err.Error()))

			return
		}

		defer reader.Close()
		io.Copy(rw, reader)
	}

	mux.Handle("/download.php", http.HandlerFunc(handler))

	http.ListenAndServe(":"+port, mux)
}
