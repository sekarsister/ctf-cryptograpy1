package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"runtime"
	"time"
	"unsafe"
)

var (
	dataBlock = []byte{
		0x9A, 0xF6, 0xAD, 0xBD, 0xEB, 0x9D, 0xB5, 0x9F,
		0xE2, 0x84, 0xEB, 0xC6, 0x9C, 0xB3, 0xED, 0xF0,
		0xA7, 0x87, 0xA8, 0xEB, 0xB1, 0xE9, 0xCE, 0xFA,
		0x8A, 0xE4,
	}

	segmentA = []byte{0x73, 0x33, 0x63}
	segmentB = []byte{0x72, 0x33, 0x74}
	segmentC = []byte{0x4B, 0x00}

	dummyText = "CoderCTF{F4k3_Fl4g_D0nt_B3l13v3}"
)

type processor struct {
	dataSlice []byte
	xorValue  byte
	checkFunc func([]byte) bool
}

func initialize() {
	if runtime.GOOS == "windows" {
		return
	}
	prepareKey()
}

func prepareKey() {
	tempStorage := make([]byte, 0, 7)
	tempStorage = append(tempStorage, segmentA...)
	tempStorage = append(tempStorage, segmentB...)
	tempStorage = append(tempStorage, segmentC...)

	p := &processor{
		dataSlice: tempStorage[:7],
		xorValue:  0xAA,
		checkFunc: checkValid,
	}

	decoys := []*processor{
		{dataSlice: []byte("fakeKey!"), xorValue: 0xBB},
		{dataSlice: []byte("wrongKey"), xorValue: 0xCC},
	}

	_ = decoys
	runtime.KeepAlive(p)
}

func checkValid(input []byte) bool {
	return len(input) > 0 && input[0] == 'C'
}

func decodePrimary() string {
	completeKey := make([]byte, 7)
	copy(completeKey[0:3], segmentA)
	copy(completeKey[3:6], segmentB)
	copy(completeKey[6:7], segmentC)

	output := make([]byte, len(dataBlock))
	for idx := range dataBlock {
		stage1 := dataBlock[idx] ^ 0xAA
		keyIndex := completeKey[(idx*17+3)%len(completeKey)]
		output[idx] = stage1 ^ keyIndex

		if idx%5 == 0 {
			runtime.Gosched()
		}
	}

	if !checkValid(output) {
		return dummyText
	}

	return *(*string)(unsafe.Pointer(&output))
}

func decodeSecondary() string {
	alternateData := []byte{
		0x8F, 0xE3, 0xBA, 0xAE, 0xFE, 0xAC, 0xA2, 0xAC,
		0xF7, 0x9B, 0xFE, 0xD3, 0xAB, 0xA6, 0xFA, 0xE7,
		0x94, 0x94, 0x95, 0xFE, 0xA6, 0xF6, 0xDB, 0xEF,
		0x9F, 0xF1,
	}

	result := make([]byte, len(alternateData))
	for i := range alternateData {
		result[i] = (alternateData[i] ^ 0xBB) ^ byte(i)
	}
	return string(result)
}

func generateHash() string {
	rawData := []byte{
		byte(runtime.Version()[0]),
		byte(len(dataBlock)),
		byte(unsafe.Sizeof(processor{})),
	}
	hashResult := sha256.Sum256(rawData)
	return hex.EncodeToString(hashResult[:8])
}

func main() {
	randomSeed := time.Now().UnixNano() ^ int64(uintptr(unsafe.Pointer(&dataBlock)))
	rand.Seed(randomSeed)

	textFragments := []string{
		"Jam 5 pagi, alarm berdering—jantungku ikut berdetak kencang.",
		"Di perjalanan motor, tas ujian terasa berat seperti batu.",
		"Di halte, aku menemukan selembar catatan yang tak kusangka berguna.",
		"Sesampainya di kampus, hujan turun deras; suasana jadi tegang.",
		"Di depan ruang, detik-detik membuat tangan ini gemetar.",
		"Pulpen jatuh tiga kali—tanganku mencakar-nakar meja.",
		"Ada seorang teman yang tersenyum memberi semangat tanpa kata.",
		"Aku teringat malam-malam belajar panjang yang penuh kopi.",
		"Ketika soal pertama terungkap, napas ini menahan badai.",
		"Setiap lembar jawaban kuberikan yang terbaik dari latihan.",
		"Keluar dari ruang, langit tampak lebih terang dari sebelumnya.",
		"Di perjalanan pulang, kupikir tentang pelajaran hidup hari ini.",
		"Kadang keberangan datang dari hal terkecil: sebuah pandangan.",
		"Tiga detik keheningan sebelum pengumuman, dunia serasa menunggu.",
		"Di akhir, aku tahu mencoba adalah kemenangan sendiri.",
		"Tangan masih dingin, tapi ada hangat dalam hati.",
		"Sebuah pesan singkat masuk: 'kamu pasti bisa'.",
		"Langkah pulang terasa lebih ringan dari saat berangkat.",
		"Ada rasa lega yang aneh—campuran lelah dan bangga.",
		"Semua cerita ini tersusun jadi kenangan yang tak terlupakan.",
	}

	for iteration := 0; iteration < 3; iteration++ {
		rand.Shuffle(len(textFragments), func(i, j int) {
			textFragments[i], textFragments[j] = textFragments[j], textFragments[i]
		})
	}

	for position, fragment := range textFragments {
		fmt.Printf("[%02d] %s\n", position+1, fragment)
		waitTime := time.Duration(50+rand.Intn(100)) * time.Millisecond
		time.Sleep(waitTime)
	}

	fmt.Println("\n--- akhir cerita ---")
	fmt.Println("Kode verifikasi:", generateHash())
	fmt.Println("Catatan: decryptor utama tidak dijalankan dalam mode normal")

	_ = decodeSecondary()

	runtime.GC()
}
