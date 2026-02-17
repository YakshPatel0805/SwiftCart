import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Product } from '../types';
import { wishlistAPI } from '../services/api';
import { useAuth } from './AuthContext';

interface WishlistContextType {
  wishlist: Product[];
  addToWishlist: (product: Product) => Promise<void>;
  removeFromWishlist: (productId: string) => Promise<void>;
  isInWishlist: (productId: string) => boolean;
  isLoading: boolean;
}

const WishlistContext = createContext<WishlistContextType | undefined>(undefined);

export function useWishlist() {
  const context = useContext(WishlistContext);
  if (context === undefined) {
    throw new Error('useWishlist must be used within a WishlistProvider');
  }
  return context;
}

interface WishlistProviderProps {
  children: ReactNode;
}

export function WishlistProvider({ children }: WishlistProviderProps) {
  const [wishlist, setWishlist] = useState<Product[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const { user } = useAuth();

  useEffect(() => {
    if (user) {
      loadWishlist();
    } else {
      setWishlist([]);
    }
  }, [user]);

  const loadWishlist = async () => {
    try {
      setIsLoading(true);
      const data = await wishlistAPI.get();
      setWishlist(data.map((p: any) => ({ ...p, id: p._id || p.id })));
    } catch (error) {
      console.error('Error loading wishlist:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const addToWishlist = async (product: Product) => {
    try {
      const productId = product.id || (product as any)._id;
      const data = await wishlistAPI.add(productId);
      setWishlist(data.map((p: any) => ({ ...p, id: p._id || p.id })));
    } catch (error) {
      console.error('Error adding to wishlist:', error);
    }
  };

  const removeFromWishlist = async (productId: string) => {
    try {
      const data = await wishlistAPI.remove(productId);
      setWishlist(data.map((p: any) => ({ ...p, id: p._id || p.id })));
    } catch (error) {
      console.error('Error removing from wishlist:', error);
    }
  };

  const isInWishlist = (productId: string) => {
    return wishlist.some(item => {
      const itemId = item.id || (item as any)._id;
      return itemId === productId;
    });
  };

  const value: WishlistContextType = {
    wishlist,
    addToWishlist,
    removeFromWishlist,
    isInWishlist,
    isLoading,
  };

  return <WishlistContext.Provider value={value}>{children}</WishlistContext.Provider>;
}
