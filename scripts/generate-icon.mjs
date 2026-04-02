import fs from "node:fs";
import path from "node:path";

const OUTPUT_DIR = path.resolve("build");
const OUTPUT_FILE = path.join(OUTPUT_DIR, "icon.ico");
const SIZES = [16, 24, 32, 48, 64, 128, 256];

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function smoothstep(edge0, edge1, x) {
  const t = clamp((x - edge0) / (edge1 - edge0), 0, 1);
  return t * t * (3 - 2 * t);
}

function alphaFromDistance(distance, softness = 1.25) {
  return 1 - smoothstep(0, softness, distance);
}

function roundedRectDistance(px, py, x, y, width, height, radius) {
  const dx = Math.abs(px - x) - width / 2 + radius;
  const dy = Math.abs(py - y) - height / 2 + radius;
  const ax = Math.max(dx, 0);
  const ay = Math.max(dy, 0);
  return Math.hypot(ax, ay) + Math.min(Math.max(dx, dy), 0) - radius;
}

function circleDistance(px, py, cx, cy, radius) {
  return Math.hypot(px - cx, py - cy) - radius;
}

function blendPixel(data, size, x, y, color, alpha) {
  if (alpha <= 0) {
    return;
  }

  const index = (y * size + x) * 4;
  const sourceAlpha = clamp(alpha, 0, 1);
  const targetAlpha = data[index + 3] / 255;
  const outAlpha = sourceAlpha + targetAlpha * (1 - sourceAlpha);

  if (outAlpha <= 0) {
    return;
  }

  data[index] = Math.round((color[0] * sourceAlpha + data[index] * targetAlpha * (1 - sourceAlpha)) / outAlpha);
  data[index + 1] = Math.round(
    (color[1] * sourceAlpha + data[index + 1] * targetAlpha * (1 - sourceAlpha)) / outAlpha,
  );
  data[index + 2] = Math.round(
    (color[2] * sourceAlpha + data[index + 2] * targetAlpha * (1 - sourceAlpha)) / outAlpha,
  );
  data[index + 3] = Math.round(outAlpha * 255);
}

function renderIcon(size) {
  const data = new Uint8ClampedArray(size * size * 4);
  const background = [26, 115, 232];
  const foreground = [255, 255, 255];

  const inset = size * 0.08;
  const cornerRadius = size * 0.22;
  const ringRadius = size * 0.225;
  const ringThickness = Math.max(2, size * 0.075);
  const centerX = size * 0.5;
  const centerY = size * 0.42;
  const dotRadius = Math.max(1.5, size * 0.04);
  const barBaseY = size * 0.72;
  const barWidth = size * 0.09;
  const barRadius = barWidth / 2;
  const barGap = size * 0.055;
  const bars = [
    { x: centerX - barWidth - barGap, height: size * 0.14 },
    { x: centerX, height: size * 0.19 },
    { x: centerX + barWidth + barGap, height: size * 0.12 },
  ];

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const px = x + 0.5;
      const py = y + 0.5;

      const backgroundDistance = roundedRectDistance(
        px,
        py,
        size / 2,
        size / 2,
        size - inset * 2,
        size - inset * 2,
        cornerRadius,
      );
      const backgroundAlpha = alphaFromDistance(backgroundDistance);
      blendPixel(data, size, x, y, background, backgroundAlpha);

      const circle = Math.abs(circleDistance(px, py, centerX, centerY, ringRadius)) - ringThickness / 2;
      const ringAlpha = alphaFromDistance(circle, 1);
      blendPixel(data, size, x, y, foreground, ringAlpha);

      const markerDistance = circleDistance(px, py, centerX + ringRadius * 0.55, centerY - ringRadius * 0.52, dotRadius);
      blendPixel(data, size, x, y, foreground, alphaFromDistance(markerDistance, 0.9));

      for (const bar of bars) {
        const distance = roundedRectDistance(px, py, bar.x, barBaseY - bar.height / 2, barWidth, bar.height, barRadius);
        blendPixel(data, size, x, y, foreground, alphaFromDistance(distance, 0.9));
      }
    }
  }

  return data;
}

function rgbaToIcoBitmap(size, rgba) {
  const header = Buffer.alloc(40);
  header.writeUInt32LE(40, 0);
  header.writeInt32LE(size, 4);
  header.writeInt32LE(size * 2, 8);
  header.writeUInt16LE(1, 12);
  header.writeUInt16LE(32, 14);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(size * size * 4, 20);
  header.writeInt32LE(0, 24);
  header.writeInt32LE(0, 28);
  header.writeUInt32LE(0, 32);
  header.writeUInt32LE(0, 36);

  const xorBitmap = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const srcIndex = ((size - 1 - y) * size + x) * 4;
      const destIndex = (y * size + x) * 4;
      xorBitmap[destIndex] = rgba[srcIndex + 2];
      xorBitmap[destIndex + 1] = rgba[srcIndex + 1];
      xorBitmap[destIndex + 2] = rgba[srcIndex];
      xorBitmap[destIndex + 3] = rgba[srcIndex + 3];
    }
  }

  const maskStride = Math.ceil(size / 32) * 4;
  const andMask = Buffer.alloc(maskStride * size);
  return Buffer.concat([header, xorBitmap, andMask]);
}

function buildIco() {
  const images = SIZES.map((size) => {
    const bitmap = rgbaToIcoBitmap(size, renderIcon(size));
    return { size, bitmap };
  });

  const directory = Buffer.alloc(6 + images.length * 16);
  directory.writeUInt16LE(0, 0);
  directory.writeUInt16LE(1, 2);
  directory.writeUInt16LE(images.length, 4);

  let offset = directory.length;
  images.forEach((image, index) => {
    const entryOffset = 6 + index * 16;
    directory.writeUInt8(image.size === 256 ? 0 : image.size, entryOffset);
    directory.writeUInt8(image.size === 256 ? 0 : image.size, entryOffset + 1);
    directory.writeUInt8(0, entryOffset + 2);
    directory.writeUInt8(0, entryOffset + 3);
    directory.writeUInt16LE(1, entryOffset + 4);
    directory.writeUInt16LE(32, entryOffset + 6);
    directory.writeUInt32LE(image.bitmap.length, entryOffset + 8);
    directory.writeUInt32LE(offset, entryOffset + 12);
    offset += image.bitmap.length;
  });

  return Buffer.concat([directory, ...images.map((image) => image.bitmap)]);
}

fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.writeFileSync(OUTPUT_FILE, buildIco());
console.log(`Generated ${OUTPUT_FILE}`);
