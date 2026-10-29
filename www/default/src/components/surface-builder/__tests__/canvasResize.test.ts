import { resizeNeedsRebuild } from '../canvasResize';

describe('resizeNeedsRebuild', () => {
  const drawn = { w: 800, h: 600 };

  it('ignores a hidden container', () => {
    expect(resizeNeedsRebuild(drawn, { w: 0, h: 0 }, false)).toBe(false);
    expect(resizeNeedsRebuild(drawn, { w: 0, h: 0 }, true)).toBe(false);
    expect(resizeNeedsRebuild(drawn, { w: 800, h: 0 }, true)).toBe(false);
  });

  it('rebuilds when the size changed by a pixel or more', () => {
    expect(resizeNeedsRebuild(drawn, { w: 801, h: 600 }, false)).toBe(true);
    expect(resizeNeedsRebuild(drawn, { w: 800, h: 599 }, false)).toBe(true);
    expect(resizeNeedsRebuild({ w: 0, h: 0 }, drawn, false)).toBe(true);
  });

  it('does not rebuild a visible container of the same size with nothing left undrawn', () => {
    expect(resizeNeedsRebuild(drawn, { w: 800, h: 600 }, false)).toBe(false);
    expect(resizeNeedsRebuild(drawn, { w: 800.4, h: 600.4 }, false)).toBe(false);
  });

  it('rebuilds a container of the same size when the last rebuild found it hidden', () => {
    expect(resizeNeedsRebuild(drawn, { w: 800, h: 600 }, true)).toBe(true);
  });
});
