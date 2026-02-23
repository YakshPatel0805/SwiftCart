import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User } from '../types';
import { authAPI } from '../services/api';

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<boolean>;
  signup: (email: string, username: string, password: string, role:string) => Promise<boolean>;
  logout: () => void;
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
          role: data.user.role || 'user',
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

  const signup = async (email: string, username: string, password: string, role: string): Promise<boolean> => {
    try {
      const data = await authAPI.signup(email, username, password, role);
      
      if (data.token && data.user) {
        const userProfile: User = {
          id: data.user.id,
          email: data.user.email,
          username: data.user.username,
          role: data.user.role,
        };
        setUser(userProfile);
        localStorage.setItem('user', JSON.stringify(userProfile));
        localStorage.setItem('token', data.token);
        return true;
      }
      return false;
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

  const value: AuthContextType = {
    user,
    login,
    signup,
    logout,
    isLoading,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}