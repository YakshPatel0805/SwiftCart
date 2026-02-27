const API_URL = 'http://localhost:5000/api';

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` })
  };
};

export const authAPI = {
  signup: async (email: string, username: string, password: string, role: string) => {
    const response = await fetch(`${API_URL}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, username, password, role })
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || `HTTP error! status: ${response.status}`);
    }
    return data;
  },

  login: async (email: string, password: string) => {
    const response = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || `HTTP error! status: ${response.status}`);
    }
    return data;
  },

  verifyResetToken: async (token: string) => {
    const response = await fetch(`${API_URL}/auth/verify-reset-token/${token}`);
    return response.json();
  },

  changePassword: async (email: string, oldPassword: string, newPassword: string, confirmPassword: string) => {
    const response = await fetch(`${API_URL}/auth/change-password`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ email, oldPassword, newPassword, confirmPassword })
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
  },

  getCategories: async () => {
    const response = await fetch(`${API_URL}/products/categories`);
    return response.json();
  },

  uploadCSV: async (file: File) => {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const token = localStorage.getItem('token');
      const response = await fetch(`${API_URL}/products/upload-csv`, {
        method: 'POST',
        headers: {
          ...(token && { Authorization: `Bearer ${token}` }),
        },
        body: formData,
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Products API uploadCSV error:', error);
      throw error;
    }
  },

  update: async (id: string, productData: any) => {
    try {
      const response = await fetch(`${API_URL}/products/${id}`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify(productData)
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Products API update error:', error);
      throw error;
    }
  },

  delete: async (id: string) => {
    try {
      const response = await fetch(`${API_URL}/products/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Products API delete error:', error);
      throw error;
    }
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

  getAllAdmin: async () => {
    try {
      const response = await fetch(`${API_URL}/orders/admin/all`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Orders API getAllAdmin error:', error);
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
  },

  cancel: async (id: string) => {
    try {
      const response = await fetch(`${API_URL}/orders/${id}/cancel`, {
        method: 'PATCH',
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Orders API cancel error:', error);
      throw error;
    }
  },

  updateStatus: async (id: string, status: string) => {
    try {
      const response = await fetch(`${API_URL}/orders/${id}/status`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify({ status })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Orders API updateStatus error:', error);
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

export const contactAPI = {
  submit: async (contactData: { name: string; email: string; subject: string; message: string }) => {
    const response = await fetch(`${API_URL}/contact/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(contactData)
    });
    return response.json();
  }
};

export const paymentAPI = {
  accountTransfer: async (data: {
    orderId: string;
    accountNumber: string;
    IFSCCode: string;
    pin: string;
  }) => {
    const res = await fetch(`${API_URL}/payment/accounttransfer`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(data)
    });

    if (!res.ok) throw await res.json();
    return res.json();
  }
};