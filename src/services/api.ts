const API_URL = 'http://localhost:5000/api';

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` })
  };
};

export const authAPI = {
  signup: async (email: string, username: string, password: string) => {
    const response = await fetch(`${API_URL}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, username, password })
    });
    return response.json();
  },

  login: async (email: string, password: string) => {
    const response = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return response.json();
  }
};

export const productsAPI = {
  getAll: async () => {
    const response = await fetch(`${API_URL}/products`);
    return response.json();
  },

  getById: async (id: string) => {
    const response = await fetch(`${API_URL}/products/${id}`);
    return response.json();
  }
};

export const ordersAPI = {
  getAll: async () => {
    try {
      const response = await fetch(`${API_URL}/orders`, {
        headers: getAuthHeaders()
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return response.json();
    } catch (error) {
      console.error('Orders API getAll error:', error);
      throw error;
    }
  },

  getById: async (id: string) => {
    const response = await fetch(`${API_URL}/orders/${id}`, {
      headers: getAuthHeaders()
    });
    return response.json();
  },

  create: async (orderData: any) => {
    try {
      const response = await fetch(`${API_URL}/orders`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(orderData)
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      
      return data;
    } catch (error) {
      console.error('Orders API create error:', error);
      throw error;
    }
  }
};

export const wishlistAPI = {
  get: async () => {
    const response = await fetch(`${API_URL}/wishlist`, {
      headers: getAuthHeaders()
    });
    return response.json();
  },

  add: async (productId: string) => {
    const response = await fetch(`${API_URL}/wishlist/${productId}`, {
      method: 'POST',
      headers: getAuthHeaders()
    });
    return response.json();
  },

  remove: async (productId: string) => {
    const response = await fetch(`${API_URL}/wishlist/${productId}`, {
      method: 'DELETE',
      headers: getAuthHeaders()
    });
    return response.json();
  }
};
