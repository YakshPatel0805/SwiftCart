import { ShippingAddress } from '../types';

const API_URL = 'http://localhost:5000/api';

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` })
  };
};

export const authAPI = {
  signup: async (email: string, username: string, password: string, role: string, mobile: string) => {
    const response = await fetch(`${API_URL}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, username, password, role, mobile })
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
  },

  updateProfile: async (username: string, email: string, mobile?: string) => {
    const response = await fetch(`${API_URL}/auth/update-profile`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ username, email, mobile })
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || `HTTP error! status: ${response.status}`);
    }
    return data;
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

  updateStatus: async (id: string, status: string, shippingStatus?: string, trackingNumber?: string, estimatedDelivery?: string) => {
    try {
      const response = await fetch(`${API_URL}/orders/${id}/status`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify({ status, shippingStatus, trackingNumber, estimatedDelivery })
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
  },

  clearAll: async () => {
    try {
      const response = await fetch(`${API_URL}/orders/clear`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Orders API clearAll error:', error);
      throw error;
    }
  },

  getDeliveryBoyOrders: async () => {
    try {
      const response = await fetch(`${API_URL}/orders/deliveryboy/all`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Orders API getDeliveryBoyOrders error:', error);
      throw error;
    }
  },

  updateDeliveryBoyOrderStatus: async (id: string, status: 'shipped' | 'delivered') => {
    try {
      const response = await fetch(`${API_URL}/orders/deliveryboy/${id}/status`, {
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
      console.error('Orders API updateDeliveryBoyOrderStatus error:', error);
      throw error;
    }
  },

  track: async (id: string) => {
    try {
      const response = await fetch(`${API_URL}/orders/${id}/track`, {
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Orders API track error:', error);
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
    pin: string;
  }) => {
    const res = await fetch(`${API_URL}/payments/accounttransfer`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      const errorData = await res.json();
      throw errorData;
    }
    return res.json();
  },

  creditCard: async (data: {
    orderId: string;
    cardNumber: string;
    cvv: string;
    expiry: string;
  }) => {
    const res = await fetch(`${API_URL}/payments/creditcard`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      const errorData = await res.json();
      throw errorData;
    }
    return res.json();
  },

  googlePay: async (data: {
    orderId: string;
    accountId: string;
  }) => {
    const res = await fetch(`${API_URL}/payments/googlepay`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      const errorData = await res.json();
      throw errorData;
    }
    return res.json();
  },

  createWithAccountTransfer: async (data: {
    items: { productId: string; quantity: number }[];
    total: number;
    shippingAddress: ShippingAddress;
    paymentMethod: { type: string };
    accountNumber: string;
    pin: string;
  }) => {
    const res = await fetch(`${API_URL}/payments/create-with-account-transfer`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      const errorData = await res.json();
      throw errorData;
    }
    return res.json();
  },

  createWithCreditCard: async (data: {
    items: { productId: string; quantity: number }[];
    total: number;
    shippingAddress: ShippingAddress;
    paymentMethod: { type: string };
    cardNumber: string;
    cvv: string;
    expiry: string;
  }) => {
    const res = await fetch(`${API_URL}/payments/create-with-credit-card`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      const errorData = await res.json();
      throw errorData;
    }
    return res.json();
  },

  createWithGooglePay: async (data: {
    items: { productId: string; quantity: number }[];
    total: number;
    shippingAddress: ShippingAddress;
    paymentMethod: { type: string };
    accountId: string;
  }) => {
    const res = await fetch(`${API_URL}/payments/create-with-googlepay`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify(data)
    });

    if (!res.ok) {
      const errorData = await res.json();
      throw errorData;
    }
    return res.json();
  }
};

export const deliveryRequestAPI = {
  sendRequests: async (orderId: string) => {
    try {
      const response = await fetch(`${API_URL}/delivery-requests/send/${orderId}`, {
        method: 'POST',
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Delivery Request API sendRequests error:', error);
      throw error;
    }
  },

  getPendingRequests: async () => {
    try {
      const response = await fetch(`${API_URL}/delivery-requests/pending`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Delivery Request API getPendingRequests error:', error);
      throw error;
    }
  },

  getAllRequests: async () => {
    try {
      const response = await fetch(`${API_URL}/delivery-requests`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Delivery Request API getAllRequests error:', error);
      throw error;
    }
  },

  acceptRequest: async (requestId: string) => {
    try {
      const response = await fetch(`${API_URL}/delivery-requests/${requestId}/accept`, {
        method: 'PATCH',
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Delivery Request API acceptRequest error:', error);
      throw error;
    }
  },

  rejectRequest: async (requestId: string) => {
    try {
      const response = await fetch(`${API_URL}/delivery-requests/${requestId}/reject`, {
        method: 'PATCH',
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Delivery Request API rejectRequest error:', error);
      throw error;
    }
  },

  getOrderRequests: async (orderId: string) => {
    try {
      const response = await fetch(`${API_URL}/delivery-requests/order/${orderId}`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Delivery Request API getOrderRequests error:', error);
      throw error;
    }
  }
};

export const usersAPI = {
  getAll: async () => {
    try {
      const response = await fetch(`${API_URL}/users`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Users API getAll error:', error);
      throw error;
    }
  },

  updateRole: async (userId: string, role: string) => {
    try {
      const response = await fetch(`${API_URL}/users/${userId}/role`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify({ role })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Users API updateRole error:', error);
      throw error;
    }
  },

  getById: async (userId: string) => {
    try {
      const response = await fetch(`${API_URL}/users/${userId}`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Users API getById error:', error);
      throw error;
    }
  }
};

export const bankAPI = {
  getAll: async () => {
    try {
      const response = await fetch(`${API_URL}/bank`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Bank API getAll error:', error);
      throw error;
    }
  },

  getById: async (accountId: string) => {
    try {
      const response = await fetch(`${API_URL}/bank/${accountId}`, {
        headers: getAuthHeaders()
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    } catch (error) {
      console.error('Bank API getById error:', error);
      throw error;
    }
  },

  add: async (accountData: any) => {
    try {
      const response = await fetch(`${API_URL}/bank`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(accountData)
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Bank API add error:', error);
      throw error;
    }
  },

  update: async (accountId: string, accountData: any) => {
    try {
      const response = await fetch(`${API_URL}/bank/${accountId}`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify(accountData)
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Bank API update error:', error);
      throw error;
    }
  },

  delete: async (accountId: string) => {
    try {
      const response = await fetch(`${API_URL}/bank/${accountId}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Bank API delete error:', error);
      throw error;
    }
  },

  setDefault: async (accountId: string) => {
    try {
      const response = await fetch(`${API_URL}/bank/${accountId}/set-default`, {
        method: 'PATCH',
        headers: getAuthHeaders()
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }
      return data;
    } catch (error) {
      console.error('Bank API setDefault error:', error);
      throw error;
    }
  }
};