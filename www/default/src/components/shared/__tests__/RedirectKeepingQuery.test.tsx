import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import RedirectKeepingQuery from '../RedirectKeepingQuery';

const Where: React.FC = () => {
  const { pathname, search, hash } = useLocation();
  return <div data-testid="where">{`${pathname}${search}${hash}`}</div>;
};

const renderAt = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/x402payments" element={<RedirectKeepingQuery to="/payments" />} />
        <Route path="/payments" element={<Where />} />
      </Routes>
    </MemoryRouter>
  );

describe('RedirectKeepingQuery', () => {
  it('keeps the query string', () => {
    renderAt('/x402payments?surface_id=x');
    expect(screen.getByTestId('where')).toHaveTextContent('/payments?surface_id=x');
  });

  it('keeps the query string and the hash together', () => {
    renderAt('/x402payments?surface_id=x&outcome=held#top');
    expect(screen.getByTestId('where')).toHaveTextContent(
      '/payments?surface_id=x&outcome=held#top'
    );
  });

  it('adds nothing when the old address had neither', () => {
    renderAt('/x402payments');
    expect(screen.getByTestId('where').textContent).toBe('/payments');
  });
});
