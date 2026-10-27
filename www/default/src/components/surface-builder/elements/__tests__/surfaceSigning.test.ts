import { isSigningEmpty } from '../types';
import type { SurfaceSigning } from '../types';

describe('surface signing config', () => {
  describe('isSigningEmpty', () => {
    it('treats an absent block as empty', () => {
      expect(isSigningEmpty(undefined)).toBe(true);
    });

    it('treats an all-blank block as empty, matching the backend is_empty()', () => {
      expect(isSigningEmpty({})).toBe(true);
    });

    it.each<[string, SurfaceSigning]>([
      ['backend', { backend: 'local' }],
      ['connection', { connection_id: 'vta-a' }],
      ['context', { context_id: 'ctx' }],
      ['key', { key_id: 'key-1' }],
    ])('treats a block with only a %s as configured', (_label, signing) => {
      expect(isSigningEmpty(signing)).toBe(false);
    });
  });

  /**
   * The distinction that matters on the wire: the backend treats "no signing"
   * and "empty signing" alike, so sending an empty block would make a surface
   * that inherits the appliance default look deliberately configured — and the
   * Key Management tab renders `inherit` from exactly that absence.
   */
  describe('what reaches the wire', () => {
    const buildSigningSlice = (signing?: SurfaceSigning) =>
      isSigningEmpty(signing) ? {} : { signing };

    it('omits the block entirely when the surface inherits', () => {
      expect(buildSigningSlice(undefined)).not.toHaveProperty('signing');
      expect(buildSigningSlice({})).not.toHaveProperty('signing');
    });

    it('sends the block when a backend is chosen', () => {
      const signing: SurfaceSigning = {
        backend: 'vta',
        connection_id: 'vta-a',
        context_id: 'ctx',
        key_id: 'key-1',
      };
      expect(buildSigningSlice(signing)).toEqual({ signing });
    });
  });
});
