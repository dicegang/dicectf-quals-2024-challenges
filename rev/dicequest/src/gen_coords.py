#!/usr/bin/env python3

from PIL import Image, ImageDraw, ImageFont

def text_to_pixel_coordinates(text, font_size=14):
    # space between each letter to make it clearer
    text = " ".join(text)
    img = Image.new('RGB', (font_size//2 * len(text), font_size), color='white')
    font = ImageFont.truetype("font.ttf", font_size)
    draw = ImageDraw.Draw(img)
    draw.text((0, 0), text, font=font, fill="black")
    # flip to match bevy coord system
    img = img.transpose(Image.FLIP_TOP_BOTTOM)
    pixel_data = list(img.getdata())
    width = img.width
    coordinates = [(i % width, i // width) for i, pixel in enumerate(pixel_data) if pixel != (255, 255, 255)]
    return coordinates

text = "dice{your_flag_is_not_in_another_castle}"
coordinates = text_to_pixel_coordinates(text)
print(f"#![allow(warnings)]\n#[rustfmt::skip]\npub const GEN_FLAG_COORDS: &[(usize, usize)] = &{coordinates};")
