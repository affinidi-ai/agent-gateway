import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Hook for implementing a two-step delete pattern
 * First click: Delete icon changes to warning triangle
 * Second click: Executes the delete (shows spinner while processing)
 * Click anywhere else: Cancels the delete
 */
export function useTwoStepDelete(onDelete: () => void | Promise<void>) {
  const [isConfirming, setIsConfirming] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Handle click outside to cancel
  useEffect(() => {
    if (!isConfirming) return;

    const handleClickOutside = (event: MouseEvent) => {
      if (buttonRef.current && !buttonRef.current.contains(event.target as Node)) {
        setIsConfirming(false);
      }
    };

    // Add listener after a small delay to avoid immediate cancellation
    const timeoutId = setTimeout(() => {
      document.addEventListener('mousedown', handleClickOutside);
    }, 100);

    return () => {
      clearTimeout(timeoutId);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isConfirming]);

  const handleClick = useCallback(
    async (e: React.MouseEvent) => {
      e.stopPropagation();

      if (!isConfirming) {
        // First click - enter confirmation mode
        setIsConfirming(true);
      } else {
        // Second click - execute delete
        setIsConfirming(false);
        setIsProcessing(true);
        try {
          await onDelete();
        } finally {
          setIsProcessing(false);
        }
      }
    },
    [isConfirming, onDelete]
  );

  const cancel = useCallback(() => {
    setIsConfirming(false);
  }, []);

  return {
    isConfirming,
    isProcessing,
    handleClick,
    cancel,
    buttonRef,
  };
}
