// src/utils/constant-time.ts
// A timing-safe string comparison shared by the security-sensitive seams that compare a
// presented secret/verifier against a stored one (PKCE verification in the grant flow,
// client-secret verification in client authentication). Logger-free and unit-testable to
// the repo's 100% line + 100% mutation gates.
import {timingSafeEqual} from 'node:crypto';

/**
 * Constant-time string compare. Returns false (never throws) on a length mismatch — length is
 * not itself the secret, and `timingSafeEqual` requires equal-length buffers. Otherwise the
 * comparison time does not depend on where the first differing byte is.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    return false;
  }
  return timingSafeEqual(ab, bb);
}
