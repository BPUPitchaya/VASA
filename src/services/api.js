import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

export const scanTarget = async (target) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/scan`, {
      target: target.target,
      scan_type: target.scanType
    });
    return response.data;
  } catch (error) {
    throw new Error(error.response?.data?.error || 'Failed to perform scan');
  }
};

export const getScanHistory = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/scans`);
    return response.data;
  } catch (error) {
    throw new Error('Failed to fetch scan history');
  }
};

export const getScanDetails = async (scanId) => {
  try {
    const response = await axios.get(`${API_BASE_URL}/scans/${scanId}`);
    return response.data;
  } catch (error) {
    throw new Error('Failed to fetch scan details');
  }
};
