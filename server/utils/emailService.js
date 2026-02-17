import nodemailer from 'nodemailer';

// Create transporter
const createTransporter = () => {
  // For development, you can use Gmail or any SMTP service
  // For production, use services like SendGrid, AWS SES, etc.
  
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
};

// Send order confirmation email
export const sendOrderConfirmationEmail = async (order, userEmail) => {
  try {
    const transporter = createTransporter();
    
    const itemsList = order.items.map(item => {
      const product = item.productSnapshot || item.product;
      return `
        <tr>
          <td style="padding: 10px; border-bottom: 1px solid #eee;">
            ${product.name}
          </td>
          <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: center;">
            ${item.quantity}
          </td>
          <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: right;">
            $${(product.price * item.quantity).toFixed(2)}
          </td>
        </tr>
      `;
    }).join('');

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: userEmail,
      subject: `Order Confirmation - Order #${order._id}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #2563eb; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9fafb; }
            .order-details { background-color: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            table { width: 100%; border-collapse: collapse; }
            .total { font-size: 18px; font-weight: bold; color: #2563eb; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Order Confirmed!</h1>
            </div>
            <div class="content">
              <p>Thank you for your order! We're processing it now.</p>
              
              <div class="order-details">
                <h2>Order Details</h2>
                <p><strong>Order ID:</strong> ${order._id}</p>
                <p><strong>Order Date:</strong> ${new Date(order.createdAt).toLocaleDateString()}</p>
                <p><strong>Payment Method:</strong> ${order.paymentMethod.type.replace('-', ' ').toUpperCase()}</p>
                
                <h3>Items:</h3>
                <table>
                  <thead>
                    <tr style="background-color: #f3f4f6;">
                      <th style="padding: 10px; text-align: left;">Product</th>
                      <th style="padding: 10px; text-align: center;">Quantity</th>
                      <th style="padding: 10px; text-align: right;">Price</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${itemsList}
                  </tbody>
                </table>
                
                <p class="total" style="text-align: right; margin-top: 20px;">
                  Total: $${order.total.toFixed(2)}
                </p>
                
                <h3>Shipping Address:</h3>
                <p>
                  ${order.shippingAddress.name}<br>
                  ${order.shippingAddress.address}<br>
                  ${order.shippingAddress.city}, ${order.shippingAddress.state} ${order.shippingAddress.zipcode}<br>
                  ${order.shippingAddress.country}
                </p>
              </div>
              
              <p>You can track your order status in your account dashboard.</p>
            </div>
            <div class="footer">
              <p>© 2024 SwiftCart. All rights reserved.</p>
              <p>This is an automated email. Please do not reply.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Order confirmation email sent to:', userEmail);
    return true;
  } catch (error) {
    console.error('Error sending order confirmation email:', error);
    return false;
  }
};

// Send order cancellation email
export const sendOrderCancellationEmail = async (order, userEmail) => {
  try {
    const transporter = createTransporter();
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: userEmail,
      subject: `Order Cancelled - Order #${order._id}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #dc2626; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9fafb; }
            .order-details { background-color: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Order Cancelled</h1>
            </div>
            <div class="content">
              <p>Your order has been successfully cancelled.</p>
              
              <div class="order-details">
                <h2>Cancelled Order Details</h2>
                <p><strong>Order ID:</strong> ${order._id}</p>
                <p><strong>Order Date:</strong> ${new Date(order.createdAt).toLocaleDateString()}</p>
                <p><strong>Cancellation Date:</strong> ${new Date().toLocaleDateString()}</p>
                <p><strong>Total Amount:</strong> $${order.total.toFixed(2)}</p>
              </div>
              
              <p>If you paid for this order, a refund will be processed within 5-7 business days.</p>
              <p>If you have any questions, please contact our customer support.</p>
            </div>
            <div class="footer">
              <p>© 2024 SwiftCart. All rights reserved.</p>
              <p>This is an automated email. Please do not reply.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Order cancellation email sent to:', userEmail);
    return true;
  } catch (error) {
    console.error('Error sending order cancellation email:', error);
    return false;
  }
};

// Send payment confirmation email
export const sendPaymentConfirmationEmail = async (order, userEmail) => {
  try {
    const transporter = createTransporter();
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: userEmail,
      subject: `Payment Confirmed - Order #${order._id}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #16a34a; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9fafb; }
            .payment-details { background-color: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .amount { font-size: 24px; font-weight: bold; color: #16a34a; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Payment Confirmed!</h1>
            </div>
            <div class="content">
              <p>We have received your payment successfully.</p>
              
              <div class="payment-details">
                <h2>Payment Details</h2>
                <p><strong>Order ID:</strong> ${order._id}</p>
                <p><strong>Payment Date:</strong> ${new Date().toLocaleDateString()}</p>
                <p><strong>Payment Method:</strong> ${order.paymentMethod.type.replace('-', ' ').toUpperCase()}</p>
                
                <p class="amount" style="text-align: center; margin: 20px 0;">
                  Amount Paid: $${order.total.toFixed(2)}
                </p>
                
                <p><strong>Status:</strong> Payment Successful</p>
              </div>
              
              <p>Your order is now being processed and will be shipped soon.</p>
              <p>You can track your order status in your account dashboard.</p>
            </div>
            <div class="footer">
              <p>© 2024 SwiftCart. All rights reserved.</p>
              <p>This is an automated email. Please do not reply.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Payment confirmation email sent to:', userEmail);
    return true;
  } catch (error) {
    console.error('Error sending payment confirmation email:', error);
    return false;
  }
};

// Send admin notification for new order
export const sendAdminOrderNotification = async (order, customerEmail, customerName) => {
  try {
    const transporter = createTransporter();
    
    const itemsList = order.items.map(item => {
      const product = item.productSnapshot || item.product;
      return `
        <tr>
          <td style="padding: 10px; border-bottom: 1px solid #eee;">
            ${product.name}
          </td>
          <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: center;">
            ${item.quantity}
          </td>
          <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: right;">
            $${(product.price * item.quantity).toFixed(2)}
          </td>
        </tr>
      `;
    }).join('');

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
      subject: `🔔 New Order Received - Order #${order._id}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #7c3aed; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9fafb; }
            .order-details { background-color: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .alert { background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; }
            table { width: 100%; border-collapse: collapse; }
            .total { font-size: 18px; font-weight: bold; color: #7c3aed; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔔 New Order Received</h1>
            </div>
            <div class="content">
              <div class="alert">
                <strong>Action Required:</strong> A new order has been placed and requires processing.
              </div>
              
              <div class="order-details">
                <h2>Order Information</h2>
                <p><strong>Order ID:</strong> ${order._id}</p>
                <p><strong>Order Date:</strong> ${new Date(order.createdAt).toLocaleDateString()} ${new Date(order.createdAt).toLocaleTimeString()}</p>
                <p><strong>Customer:</strong> ${customerName}</p>
                <p><strong>Customer Email:</strong> ${customerEmail}</p>
                <p><strong>Payment Method:</strong> ${order.paymentMethod.type.replace('-', ' ').toUpperCase()}</p>
                <p><strong>Status:</strong> ${order.status.toUpperCase()}</p>
                
                <h3>Items Ordered:</h3>
                <table>
                  <thead>
                    <tr style="background-color: #f3f4f6;">
                      <th style="padding: 10px; text-align: left;">Product</th>
                      <th style="padding: 10px; text-align: center;">Quantity</th>
                      <th style="padding: 10px; text-align: right;">Price</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${itemsList}
                  </tbody>
                </table>
                
                <p class="total" style="text-align: right; margin-top: 20px;">
                  Total: $${order.total.toFixed(2)}
                </p>
                
                <h3>Shipping Address:</h3>
                <p>
                  ${order.shippingAddress.name}<br>
                  ${order.shippingAddress.address}<br>
                  ${order.shippingAddress.city}, ${order.shippingAddress.state} ${order.shippingAddress.zipcode}<br>
                  ${order.shippingAddress.country}<br>
                  <strong>Phone:</strong> ${order.shippingAddress.phone || 'Not provided'}
                </p>
              </div>
              
              <p><strong>Next Steps:</strong></p>
              <ul>
                <li>Process the order in the admin panel</li>
                <li>Prepare items for shipping</li>
                <li>Update order status when shipped</li>
              </ul>
            </div>
            <div class="footer">
              <p>© 2024 SwiftCart Admin Notification</p>
              <p>This is an automated admin notification.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Admin order notification sent');
    return true;
  } catch (error) {
    console.error('Error sending admin order notification:', error);
    return false;
  }
};

// Send admin notification for order cancellation
export const sendAdminCancellationNotification = async (order, customerEmail, customerName) => {
  try {
    const transporter = createTransporter();
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
      subject: `⚠️ Order Cancelled - Order #${order._id}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #dc2626; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9fafb; }
            .order-details { background-color: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .alert { background-color: #fee2e2; border-left: 4px solid #dc2626; padding: 15px; margin: 20px 0; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>⚠️ Order Cancelled</h1>
            </div>
            <div class="content">
              <div class="alert">
                <strong>Notice:</strong> A customer has cancelled their order.
              </div>
              
              <div class="order-details">
                <h2>Cancellation Details</h2>
                <p><strong>Order ID:</strong> ${order._id}</p>
                <p><strong>Original Order Date:</strong> ${new Date(order.createdAt).toLocaleDateString()}</p>
                <p><strong>Cancellation Date:</strong> ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}</p>
                <p><strong>Customer:</strong> ${customerName}</p>
                <p><strong>Customer Email:</strong> ${customerEmail}</p>
                <p><strong>Order Total:</strong> $${order.total.toFixed(2)}</p>
                <p><strong>Payment Method:</strong> ${order.paymentMethod.type.replace('-', ' ').toUpperCase()}</p>
                
                <h3>Shipping Address:</h3>
                <p>
                  ${order.shippingAddress.name}<br>
                  ${order.shippingAddress.address}<br>
                  ${order.shippingAddress.city}, ${order.shippingAddress.state} ${order.shippingAddress.zipcode}
                </p>
              </div>
              
              <p><strong>Action Required:</strong></p>
              <ul>
                <li>Stop processing if order hasn't been shipped</li>
                <li>Process refund if payment was received</li>
                <li>Update inventory if items were reserved</li>
                <li>Mark order as cancelled in admin panel</li>
              </ul>
            </div>
            <div class="footer">
              <p>© 2024 SwiftCart Admin Notification</p>
              <p>This is an automated admin notification.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Admin cancellation notification sent');
    return true;
  } catch (error) {
    console.error('Error sending admin cancellation notification:', error);
    return false;
  }
};
