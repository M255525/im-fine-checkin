# 產生 PWA 圖示：深藍磁磚牆上一扇亮燈的鐵窗
import os
from PIL import Image, ImageDraw

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'icons')


def draw(size, pad):
    s = 4 * size
    im = Image.new('RGB', (s, s), '#21406F')
    d = ImageDraw.Draw(im)
    x0, y0, x1, y1 = pad * s, pad * .9 * s, (1 - pad) * s, (1 - pad * .9) * s
    fw = s * .035
    d.rectangle([x0, y0, x1, y1], fill='#E6ECF3')
    d.rectangle([x0 + fw, y0 + fw, x1 - fw, y1 - fw], fill='#FFC72E')
    bars = 5
    w = x1 - x0 - 2 * fw
    for i in range(1, bars):
        x = x0 + fw + w * i / bars
        d.rectangle([x - s * .007, y0 + fw, x + s * .007, y1 - fw], fill='#7A5208')
    ym = (y0 + y1) / 2
    d.rectangle([x0 + fw, ym - s * .007, x1 - fw, ym + s * .007], fill='#7A5208')
    return im.resize((size, size), Image.LANCZOS)


draw(192, .2).save(os.path.join(out, 'icon-192.png'))
draw(512, .2).save(os.path.join(out, 'icon-512.png'))
draw(512, .28).save(os.path.join(out, 'icon-maskable-512.png'))
