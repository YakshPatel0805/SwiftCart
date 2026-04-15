export interface User {
  id: string;
  email: string;
  username: string;
  mobile?: string;
  role?: 'user' | 'admin' | 'deliveryboy';
  wishlist?: Product[];
}

export interface Product {
  id: string;
  name: string;
  price: number;
  image: string;
  category: string;
  description: string;
  rating: number;
  reviews: string;
  inStock: boolean;
  stockQuantity?: number;
  soldCount?: number;
}

export interface CartItem {
  product: Product;
  quantity: number;
}

export interface Order {
  id: string;
  userId: string;
  items: CartItem[];
  total: number;
  status: 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled';
  shippingAddress: ShippingAddress;
  paymentMethod: PaymentMethod;
  createdAt: string;
}

export interface ShippingAddress {
  name: string;
  email: string;
  address: string;
  city: string;
  state: string;
  zipcode: string;
  country: string;
}

export type PaymentMethod =
  | { type: 'credit-card'; cardholderName?: string; cardNumber?: string; expiryDate?: string; cvv?: string }
  | { type: 'google-pay' }
  | { type: 'cash-on-delivery' }
  | {
      type: 'Account-Transfer';
      accHolderName?: string;
      accNumber?: string;
      pin?: string;
    };

export interface Payment {
  _id: string;
  orderId: string;
  userId: string;
  amount: number;
  method: 'Account-Transfer' | 'cash-on-delivery' | 'google-pay' | 'credit-card';
  status: 'success' | 'failed' | 'pending';
  transactionId?: string;
  createdAt: Date;
}

export interface PaymentDetailsProps {
  orderId: string;
  paymentData?: Payment;
  loading?: boolean;
  error?: string;
}

export interface OrderItemsProps {
  items: Array<{
    productSnapshot?: {
      name: string;
      price: number;
      image: string;
    };
    product?: {
      name: string;
      price: number;
      image: string;
    };
    quantity: number;
  }>;
  showImages?: boolean;
}