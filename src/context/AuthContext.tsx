import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User } from '../types';
import { authAPI } from '../services/api';

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<boolean>;
  signup: (email: string, username: string, password: string, role: string, mobile: string) => Promise<boolean>;
  logout: () => void;
  updateProfile: (username: string, email: string, mobile?: string) => Promise<void>;
  recentlyViewed: string[];
  addToRecentlyViewed: (productId: string) => void;
  clearRecentlyViewed: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    const token = localStorage.getItem('token');
    if (savedUser && token) {
      setUser(JSON.parse(savedUser));
    }
    setIsLoading(false);
  }, []);

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      const data = await authAPI.login(email, password);

      if (data.token && data.user) {
        const userProfile: User = {
          id: data.user.id,
          email: data.user.email,
          username: data.user.username,
          mobile: data.user.mobile,
          role: data.user.role,
        };
        setUser(userProfile);
        localStorage.setItem('user', JSON.stringify(userProfile));
        localStorage.setItem('token', data.token);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Login error:', error);
      return false;
    }
  };

  const signup = async (
    email: string,
    username: string,
    password: string,
    role: string,
    mobile: string
  ): Promise<boolean> => {
    try {
      const data = await authAPI.signup(email, username, password, role, mobile);
      return data.success === true;
    } catch (error) {
      console.error('Signup error:', error);
      return false;
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('user');
    localStorage.removeItem('token');
  };

  const updateProfile = async (username: string, email: string, mobile?: string) => {
    try {
      const data = await authAPI.updateProfile(username, email, mobile);
      if (data.user) {
        const updatedUser: User = {
          id: data.user.id,
          email: data.user.email,
          username: data.user.username,
          mobile: data.user.mobile,
          role: data.user.role,
        };
        setUser(updatedUser);
        localStorage.setItem('user', JSON.stringify(updatedUser));
      }
    } catch (error: any) {
      console.error('Update profile error:', error);
      console.error('Error details:', error.message, error);
      throw error;
    }
  };

  const [recentlyViewed, setRecentlyViewed] = useState<string[]>(() => {
    const saved = localStorage.getItem('recentlyViewed');
    return saved ? JSON.parse(saved) : [];
  });

  const addToRecentlyViewed = (productId: string) => {
    setRecentlyViewed(prev => {
      const updated = [productId, ...prev.filter(id => id !== productId)].slice(0, 10);
      localStorage.setItem('recentlyViewed', JSON.stringify(updated));
      return updated;
    });
  };

  const clearRecentlyViewed = () => {
    setRecentlyViewed([]);
    localStorage.removeItem('recentlyViewed');
  };

  const value: AuthContextType = {
    user,
    login,
    signup,
    logout,
    updateProfile,
    recentlyViewed,
    addToRecentlyViewed,
    clearRecentlyViewed,
    isLoading,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
