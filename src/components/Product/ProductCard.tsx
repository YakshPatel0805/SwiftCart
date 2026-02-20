import React from 'react';
import { Star, ShoppingCart, Heart } from 'lucide-react';
import { Product } from '../../types';
import { useCart } from '../../context/CartContext';
import { useWishlist } from '../../context/WishlistContext';
import { useAuth } from '../../context/AuthContext';

interface ProductCardProps {
  product: Product;
}

export default function ProductCard({ product }: ProductCardProps) {
  const { addToCart } = useCart();
  const { addToWishlist, removeFromWishlist, isInWishlist } = useWishlist();
  const { user } = useAuth();

  const handleAddToCart = () => {
    addToCart(product);
  };

  const handleWishlistToggle = () => {
    if (!user) {
      alert('Please login to add items to wishlist');
      return;
    }
    
    if (isInWishlist(product.id)) {
      removeFromWishlist(product.id);
    } else {
      addToWishlist(product);
    }
  };

  const inWishlist = isInWishlist(product.id);

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden transition-transform hover:scale-105 hover:shadow-lg">
      <div className="relative overflow-hidden group">
        <img
          src={product.image}
          alt={product.name}
          className="w-full h-48 object-cover transition-transform group-hover:scale-110"
        />
        <div className="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-20 transition-opacity"></div>
        
        {/* Wishlist Button */}
        <button
          onClick={handleWishlistToggle}
          className={`absolute top-2 right-2 p-2 rounded-full transition-all ${
            inWishlist 
              ? 'bg-red-500 text-white' 
              : 'bg-white text-gray-600 hover:bg-red-50 hover:text-red-500'
          }`}
          title={inWishlist ? 'Remove from wishlist' : 'Add to wishlist'}
        >
          <Heart className={`h-5 w-5 ${inWishlist ? 'fill-current' : ''}`} />
        </button>
      </div>
      
      <div className="p-4">
        <h3 className="text-lg font-semibold text-gray-800 mb-2 line-clamp-2">
          {product.name}
        </h3>
        
        <p className="text-gray-600 text-sm mb-3 line-clamp-2">
          {product.description}
        </p>
        
        <div className="flex items-center mb-3">
          <div className="flex items-center">
            {[...Array(5)].map((_, i) => (
              <Star
                key={i}
                className={`h-4 w-4 ${
                  i < Math.floor(product.rating)
                    ? 'text-yellow-400 fill-current'
                    : 'text-gray-300'
                }`}
              />
            ))}
          </div>
          <span className="text-sm text-gray-600 ml-2">
            ({product.reviews} reviews)
          </span>
        </div>
        
        <div className="flex items-center justify-between">
          <span className="text-2xl font-bold text-blue-600">
            ${product.price.toFixed(2)}
          </span>
          
          <button
            onClick={handleAddToCart}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
          >
            <ShoppingCart className="h-4 w-4" />
            <span>Add to Cart</span>
          </button>
        </div>
        
        {!product.inStock && (
          <div className="mt-2">
            <span className="text-red-500 text-sm font-medium">Out of Stock</span>
          </div>
        )}
      </div>
    </div>
  );
}