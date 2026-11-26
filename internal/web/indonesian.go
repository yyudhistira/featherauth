package web

import "slices"

// indonesian is the built-in translation of every message id into Indonesian
// (id), FR-50. A realm's locales/id.yaml replaces single messages of it. The
// provider button texts follow Google's published wording, "Masuk dengan
// Google"; the other providers' wording was not available when it was written,
// so the owner should read them (see the pull request).
var indonesian = map[string]string{
	"chooser.title":           "Masuk",
	"chooser.prompt":          "Pilih cara Anda untuk masuk.",
	"chooser.log_in_with":     "Masuk dengan {name}",
	"chooser.sign_in_with":    "Masuk dengan {name}",
	"chooser.no_providers":    "Tidak ada metode masuk yang tersedia saat ini.",
	"data_deletion.title":     "Hapus data Anda",
	"data_deletion.in_app":    "Untuk menghapus akun dan data yang tersimpan tentang Anda, gunakan opsi hapus akun di aplikasi.",
	"data_deletion.contact":   "Jika Anda tidak dapat melakukannya, tulis ke",
	"data_deletion.confirmed": "Permintaan penghapusan segera dijalankan. Kode konfirmasi Anda adalah",
	"error.title":             "Terjadi kesalahan",
	"error.contact":           "Jika ini terus terjadi, hubungi",
	"error.invalid_request":   "Permintaan ini tidak valid, sehingga Anda tidak dapat dikembalikan ke aplikasi. Kembali ke aplikasi dan coba lagi.",
	"error.request_expired":   "Permintaan masuk ini tidak dikenal atau sudah kedaluwarsa. Kembali ke aplikasi dan coba lagi.",
	"error.realm_disabled":    "Masuk tidak tersedia saat ini.",
	"error.logout_refused":    "Permintaan keluar tidak dapat diverifikasi.",
	"error.server":            "Terjadi kesalahan di pihak kami. Coba lagi nanti.",
	"form_post.title":         "Lanjutkan",
	"form_post.body":          "Anda sedang dikembalikan ke aplikasi.",
	"form_post.button":        "Lanjutkan",
	"signed_out.title":        "Sudah keluar",
	"signed_out.body":         "Anda sudah keluar. Anda dapat menutup jendela ini.",
}

// builtin maps each built-in language other than English to its translation.
var builtin = map[string]map[string]string{"id": indonesian}

// BuiltinLanguages returns the codes of the languages with a built-in
// translation, sorted; English is built in too and has none.
func BuiltinLanguages() []string {
	out := make([]string, 0, len(builtin))
	for code := range builtin {
		out = append(out, code)
	}
	slices.Sort(out)
	return out
}

// BuiltinTranslation returns a copy of the built-in translation of code.
func BuiltinTranslation(code string) (map[string]string, bool) {
	m, ok := builtin[code]
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out, true
}
