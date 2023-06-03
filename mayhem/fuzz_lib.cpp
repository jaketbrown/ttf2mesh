#include <iostream>
#include <memory>
#include "fuzzer/FuzzedDataProvider.h"
#include "ttf2mesh.h"

class Font {
public:
    constexpr Font(const uint8_t* data, std::size_t size): font{nullptr} {
        ttf_load_from_mem(data, static_cast<int>(size), &font, false);
    }

    ~Font() {
        ttf_free(font);
    }
    Font(const Font& other) = default;
    Font(Font&& other) = default;
    Font& operator=(const Font& other) = default;
    Font& operator=(Font&& other) = default;
    ttf_t *font{};

    void load_mesh() const {
        ttf_mesh_t *out;
        if (ttf_glyph2mesh(&font->glyphs[0], &out, TTF_QUALITY_NORMAL, TTF_FEATURES_DFLT)
            != TTF_DONE)
            return;
        ttf_free_mesh(out);
    }

    void load_3D_mesh() const {
        ttf_mesh3d_t* out;
        if (ttf_glyph2mesh3d(&font->glyphs[0], &out, TTF_QUALITY_NORMAL, TTF_FEATURES_DFLT,
                             0.1f) != TTF_DONE)
            return;
        ttf_free_mesh3d(out);
    }

    void load_svg() const {
        ttf_glyph2svgpath(&font->glyphs[0], 0.1f, 0.2f);
    }

    void splitted_outline() const {
        auto *o = ttf_splitted_outline(&font->glyphs[0]);
        float p, q;
        if (o != nullptr) {
            ttf_outline_evenodd_base(o, &p, 0, &q);
        }
        ttf_free_outline(o);
    }

    void linear_outline() const {
        auto *o = ttf_linear_outline(&font->glyphs[0], TTF_QUALITY_NORMAL);
        float p;
        if (o != nullptr) {
            ttf_outline_evenodd(o, &p, 0);
        }
        ttf_free_outline(o);
    }
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 500) return -1;

    FuzzedDataProvider fdp(data, size);

    const auto symbol = static_cast<wchar_t>(data[407]);
    //const auto choice = data[408] % 5;

    const std::size_t font_size = fdp.remaining_bytes();
    std::unique_ptr<uint8_t[]> data_ptr(new uint8_t[font_size]);
    fdp.ConsumeData(data_ptr.get(), font_size);

    // Load the font
    auto font = Font(data_ptr.get(), font_size);
    if (font.font == nullptr) {
        // Failed to load font
        return 0;
    }

    // Find the glyph
    int index = ttf_find_glyph(font.font, symbol);
    if (index < 0) {
        return 0;
    }

    font.load_mesh();
    font.load_3D_mesh();
    font.load_svg();
    font.splitted_outline();
    font.linear_outline();

    return 0;
}