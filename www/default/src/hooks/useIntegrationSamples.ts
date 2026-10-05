import { useEffect, useRef, useState } from 'react';
import { fetchRuntimeVariables } from '../utils/runtimeVariables';
import {
  IntegrationContents,
  IntegrationSamples,
  buildIntegrationSamples,
  untouchedReplacements,
} from '../utils/integrationSamples';

/**
 * Keeps each integration type's untouched content in step with the category's
 * sample. Whenever `category` changes, content that is empty or still the
 * previous category's sample is handed to `apply` as the new sample; edited
 * content is left alone. Returns the current category's samples.
 */
export function useIntegrationSamples(
  category: string,
  contents: IntegrationContents,
  apply: (replacements: Partial<IntegrationContents>) => void,
  enabled = true
): IntegrationSamples | null {
  const [samples, setSamples] = useState<IntegrationSamples | null>(null);
  const previousRef = useRef<IntegrationSamples | null>(null);
  const contentsRef = useRef(contents);
  contentsRef.current = contents;
  const applyRef = useRef(apply);
  applyRef.current = apply;

  useEffect(() => {
    if (!enabled) {
      return undefined;
    }
    let cancelled = false;
    fetchRuntimeVariables().then(catalogue => {
      if (cancelled) {
        return;
      }
      const next = buildIntegrationSamples(catalogue, category || 'general');
      const replacements = untouchedReplacements(contentsRef.current, previousRef.current, next);
      previousRef.current = next;
      setSamples(next);
      if (Object.keys(replacements).length > 0) {
        applyRef.current(replacements);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [category, enabled]);

  return samples;
}
