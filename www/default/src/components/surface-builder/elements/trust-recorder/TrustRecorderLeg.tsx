import React from 'react';
import { isTransitPointTrustRecorder } from './definition';

/** Says which leg a Trust Recorder node writes on. */
const TrustRecorderLeg: React.FC<{ node?: { slotId?: string } }> = ({ node }) =>
  isTransitPointTrustRecorder(node) ? (
    <>
      Writes records to every configured Trust Registry on the <strong>request leg</strong> (Managed
      Agent &rarr; Transit Point), in the background, for the DID the managed agent calls out under.
    </>
  ) : (
    <>
      Writes records to every configured Trust Registry on the <strong>response leg</strong>{' '}
      (Managed Agent &rarr; Access Point).
    </>
  );

export default TrustRecorderLeg;
