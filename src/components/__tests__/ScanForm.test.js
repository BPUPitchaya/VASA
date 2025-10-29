import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import ScanForm from '../ScanForm';

describe('ScanForm', () => {
  const mockOnScan = jest.fn();
  
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders the form with default values', () => {
    render(<ScanForm onScan={mockOnScan} loading={false} />);
    
    expect(screen.getByLabelText('Target URL or IP:')).toBeInTheDocument();
    expect(screen.getByDisplayValue('')).toBeInTheDocument();
    expect(screen.getByLabelText('Quick Scan')).toBeChecked();
    expect(screen.getByText('Start Scan')).toBeInTheDocument();
  });

  it('calls onScan with the correct values when form is submitted', () => {
    render(<ScanForm onScan={mockOnScan} loading={false} />);
    
    const targetInput = screen.getByLabelText('Target URL or IP:');
    const submitButton = screen.getByText('Start Scan');
    
    fireEvent.change(targetInput, { target: { value: 'example.com' } });
    fireEvent.click(submitButton);
    
    expect(mockOnScan).toHaveBeenCalledTimes(1);
    expect(mockOnScan).toHaveBeenCalledWith({
      target: 'example.com',
      scanType: 'quick',
      timestamp: expect.any(String)
    });
  });

  it('disables the submit button when loading', () => {
    render(<ScanForm onScan={mockOnScan} loading={true} />);
    
    const submitButton = screen.getByText('Scanning...');
    expect(submitButton).toBeDisabled();
  });

  it('updates the scan type when radio button is clicked', () => {
    render(<ScanForm onScan={mockOnScan} loading={false} />);
    
    const fullScanRadio = screen.getByLabelText('Full Scan');
    fireEvent.click(fullScanRadio);
    
    expect(fullScanRadio).toBeChecked();
    
    const targetInput = screen.getByLabelText('Target URL or IP:');
    const submitButton = screen.getByText('Start Scan');
    
    fireEvent.change(targetInput, { target: { value: 'example.com' } });
    fireEvent.click(submitButton);
    
    expect(mockOnScan).toHaveBeenCalledWith(expect.objectContaining({
      scanType: 'full'
    }));
  });
});
