import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PaginationControls, { clampPage } from '../PaginationControls';

const controls = (
  page: number,
  total: number,
  onPageChange: (page: number) => void = jest.fn()
) => <PaginationControls page={page} pageSize={10} total={total} onPageChange={onPageChange} />;

describe('PaginationControls', () => {
  it('shows nothing for a list of one page', () => {
    render(controls(1, 10));

    expect(screen.queryByRole('navigation')).toBeNull();
    expect(screen.queryByText(/of 10/)).toBeNull();
  });

  it('shows the range of the page and marks the page that is shown', () => {
    render(controls(2, 25));

    expect(screen.getByText('11–20 of 25')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Pagination' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '2' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('button', { name: '1' })).not.toHaveAttribute('aria-current');
    expect(screen.getByRole('button', { name: '3' })).not.toHaveAttribute('aria-current');
  });

  it('opens the page a button names, and the pages before and after', () => {
    const onPageChange = jest.fn();
    render(controls(2, 25, onPageChange));

    fireEvent.click(screen.getByRole('button', { name: '3' }));
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }));
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));

    expect(onPageChange.mock.calls).toEqual([[3], [1], [3]]);
  });

  it('offers no page before the first', () => {
    const onPageChange = jest.fn();
    render(controls(1, 25, onPageChange));

    expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Next page' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }));
    expect(onPageChange).not.toHaveBeenCalled();
  });

  it('offers no page after the last', () => {
    const onPageChange = jest.fn();
    render(controls(3, 25, onPageChange));

    expect(screen.getByText('21–25 of 25')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
    expect(onPageChange).not.toHaveBeenCalled();
  });

  it('leaves out the pages far from the one shown', () => {
    render(controls(5, 100));

    expect(
      screen
        .getAllByRole('button')
        .map(button => button.textContent)
        .slice(1, -1)
    ).toEqual(['1', '4', '5', '6', '10']);
  });

  it('shows the last page left once the list no longer reaches the page asked for', () => {
    expect(clampPage(2, 10, 11)).toBe(2);
    expect(clampPage(2, 10, 10)).toBe(1);
    expect(clampPage(5, 10, 0)).toBe(1);
    expect(clampPage(0, 10, 30)).toBe(1);
  });
});
