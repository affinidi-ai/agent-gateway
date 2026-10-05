import React, { memo } from 'react';

const WRAPPER_STYLE: React.CSSProperties = {
  position: 'relative',
  display: 'inline-block',
};

const ICON_STYLE: React.CSSProperties = {
  position: 'absolute',
  left: '0.75rem',
  top: '50%',
  transform: 'translateY(-50%)',
  color: 'var(--gray-500)',
  fontSize: '0.875rem',
  pointerEvents: 'none',
};

const INPUT_STYLE: React.CSSProperties = {
  width: '384px',
  paddingLeft: '2.25rem',
  paddingRight: '2.25rem',
  border: 'none',
  fontSize: '0.875rem',
  outline: 'none',
  boxShadow: 'none',
};

const CLEAR_STYLE: React.CSSProperties = {
  position: 'absolute',
  right: '0.5rem',
  top: '50%',
  transform: 'translateY(-50%)',
  width: '1.25rem',
  height: '1.25rem',
  borderRadius: '50%',
  border: 'none',
  padding: 0,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  background: 'rgba(0, 0, 0, 0.15)',
  color: 'var(--gray-700)',
  fontSize: '0.65rem',
  cursor: 'pointer',
  lineHeight: 1,
};

interface SearchInputProps {
  value: string;
  onChange: (value: string) => void;
  width?: string;
  placeholder?: string;
  className?: string;
  wrapperStyle?: React.CSSProperties;
}

const SearchInput: React.FC<SearchInputProps> = ({
  value,
  onChange,
  placeholder = 'Filter...',
  width = '384px',
  className = 'form-control',
  wrapperStyle,
  ...rest
}) => {
  const inputStyle = width === '384px' ? INPUT_STYLE : { ...INPUT_STYLE, width };
  return (
    <div style={wrapperStyle ? { ...WRAPPER_STYLE, ...wrapperStyle } : WRAPPER_STYLE}>
      <i className="fas fa-search" style={ICON_STYLE}></i>
      <input
        type="text"
        className={`${className} search-input-field`}
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(e.target.value)}
        style={inputStyle}
        {...rest}
      />
      {value && (
        <button
          type="button"
          aria-label="Clear filter"
          onClick={() => onChange('')}
          style={CLEAR_STYLE}
        >
          <i className="fas fa-times"></i>
        </button>
      )}
    </div>
  );
};

export default memo(SearchInput);
