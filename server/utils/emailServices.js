import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.USER_EMAIL,
    pass: process.env.USER_EMAIL_PASSWORD,
    admin: process.env.ADMIN_EMAIL,
    adminPass: process.env.ADMIN_EMAIL_PASSWORD,
  },
});

const adminEmail = process.env.ADMIN_EMAIL;

const commonStyle = `
  font-family: Arial, sans-serif;
  line-height: 1.6;
  color: #333;
  max-width: 600px;
  margin: 0 auto;
  padding: 20px;
  border: 1px solid #ddd;
  border-radius: 10px;
`;

const headerStyle = `
  background-color: #4f46e5;
  color: white;
  padding: 20px;
  text-align: center;
  border-radius: 10px 10px 0 0;
  margin: -20px -20px 20px -20px;
`;

const footerStyle = `
  margin-top: 20px;
  font-size: 12px;
  color: #777;
  text-align: center;
  border-top: 1px solid #ddd;
  padding-top: 10px;
`;

const buttonStyle = `
  display: inline-block;
  padding: 10px 20px;
  background-color: #4f46e5;
  color: white;
  text-decoration: none;
  border-radius: 5px;
  margin-top: 20px;
`;

const tableStyle = `
  width: 100%;
  border-collapse: collapse;
  margin: 20px 0;
`;

const thStyle = `
  text-align: left;
  border-bottom: 2px solid #ddd;
  padding: 10px;
`;

const tdStyle = `
  padding: 10px;
  border-bottom: 1px solid #eee;
`;

// Helper to format currency
const formatCurrency = (amount) => `₹${amount.toFixed(2)}`;

// 1a. Order Confirmation (User)
export const sendOrderConfirmationEmail = async (user, order) => {
  const mailOptions = {
    from: process.env.ADMIN_EMAIL,
    to: user.email,
    subject: `Order Confirmed`,
    html: `
      <div style="${commonStyle}">
        <div style="${headerStyle}">
          <h1>SwiftCart</h1>
          <p>Order Confirmation</p>
        </div>
        <h2>Thank you for your order, ${user.username}!</h2>
        <p>Your order <strong>${order._id}</strong> has been placed successfully and is being processed.</p>
        
        <table style="${tableStyle}">
          <thead>
            <tr>
              <th style="${thStyle}">Product</th>
              <th style="${thStyle}">Qty</th>
              <th style="${thStyle}">Price</th>
            </tr>
          </thead>
          <tbody>
            ${order.items.map(item => `
              <tr>
                <td style="${tdStyle}">${item.productSnapshot.name}</td>
                <td style="${tdStyle}">${item.quantity}</td>
                <td style="${tdStyle}">${formatCurrency(item.productSnapshot.price)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        
        <p><strong>Total Amount:</strong> ${formatCurrency(order.total)}</p>
        <p><strong>Shipping Address:</strong><br>${order.shippingAddress.address}, ${order.shippingAddress.city}, ${order.shippingAddress.state}, ${order.shippingAddress.zipcode}</p>
        
        <a href="http://localhost:5173/orders/${order._id}" style="${buttonStyle}">Track Your Order</a>
        
        <div style="${footerStyle}">
          <p>&copy; 2026 SwiftCart Inc. All rights reserved.</p>
        </div>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Order confirmation email sent to ${user.email}`);
  } catch (error) {
    console.error('Error sending order confirmation email:', error);
  }
};

// 1b. Order Received (Admin)
export const sendNewOrderAdminEmail = async (order) => {
  const mailOptions = {
    from: process.env.USER_EMAIL,
    to: process.env.ADMIN_EMAIL,
    subject: `New Order Received`,
    html: `
      <div style="${commonStyle}">
        <div style="${headerStyle}">
          <h1>SwiftCart Admin</h1>
          <p>New Order Alert</p>
        </div>
        <h2>New Order Details</h2>
        <p><strong>Order ID:</strong> ${order._id}</p>
        <p><strong>Total:</strong> ${formatCurrency(order.total)}</p>
        <p><strong>Payment Method:</strong> ${order.paymentMethod.type}</p>
        
        <a href="http://localhost:5173/admin/orders/${order._id}" style="${buttonStyle}">View in Admin Panel</a>
        
        <div style="${footerStyle}">
          <p>&copy; 2026 SwiftCart Admin System.</p>
        </div>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`New order alert sent to admin: ${adminEmail}`);
  } catch (error) {
    console.error('Error sending admin order alert:', error);
  }
};


// 2. Order Cancellation (User & Admin)
export const sendOrderCancellationEmail = async (user, order, isAdminAlert = false) => {
  const subject = isAdminAlert ? `Order Cancelled by User - ${user.username}` : `Order Cancelled - ${order._id}`;
  const recipient = isAdminAlert ? process.env.ADMIN_EMAIL : user.email;
  const sender = isAdminAlert ? user.email : process.env.ADMIN_EMAIL;

  const mailOptions = {
    from: sender,
    to: recipient,
    subject: subject,
    html: `
      <div style="${commonStyle}">
        <div style="${headerStyle}; background-color: #ef4444;">
          <h1>SwiftCart</h1>
          <p>Order Cancellation</p>
        </div>
        <h2>Order ${order._id} has been cancelled.</h2>
        <p>${isAdminAlert ? `User ${user.username} cancelled their order.` : 'As per your request, your order has been cancelled successfully.'}</p>
        <p>The items will be returned to stock, and any payments made will be refunded according to our policy.</p>
        
        <div style="${footerStyle}">
          <p>&copy; 2026 SwiftCart Inc. All rights reserved.</p>
        </div>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Cancellation email sent to ${recipient}`);
  } catch (error) {
    console.error('Error sending cancellation email:', error);
  }
};

// 3. Payment Confirmation (User & Admin)
export const sendPaymentConfirmationEmail = async (user, payment, order, isAdminAlert = false) => {
  const subject = isAdminAlert ? `Payment Success Alert` : `Payment Received`;
  const recipient = isAdminAlert ? process.env.ADMIN_EMAIL : user.email;
  const sender = isAdminAlert ? user.email : process.env.ADMIN_EMAIL;

  const mailOptions = {
    from: sender,
    to: recipient,
    subject: subject,
    html: `
      <div style="${commonStyle}">
        <div style="${headerStyle}; background-color: #10b981;">
          <h1>SwiftCart</h1>
          <p>Payment Confirmation</p>
        </div>
        <h2>Payment Successful!</h2>
        <p>We've received your payment of <strong>${formatCurrency(payment.amount)}</strong> for order <strong>${order._id}</strong>.</p>
        <p><strong>Transaction ID:</strong> ${payment.transactionId}</p>
        <p><strong>Method:</strong> ${payment.method}</p>
        
        <div style="${footerStyle}">
          <p>&copy; 2026 SwiftCart Inc. All rights reserved.</p>
        </div>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Payment confirmation email sent to ${recipient}`);
  } catch (error) {
    console.error('Error sending payment confirmation email:', error);
  }
};

// 4. Order Delivered (User & Admin)
export const sendOrderDeliveredEmail = async (user, order, isAdminAlert = false) => {
  const subject = isAdminAlert ? `Order Delivered Alert` : `Order Delivered!`;
  const recipient = isAdminAlert ? process.env.ADMIN_EMAIL : user.email;
  const sender = isAdminAlert ? user.email : process.env.ADMIN_EMAIL;

  const mailOptions = {
    from: sender,
    to: recipient,
    subject: subject,
    html: `
      <div style="${commonStyle}">
        <div style="${headerStyle}; background-color: #10b981;">
          <h1>SwiftCart</h1>
          <p>Delivery Confirmation</p>
        </div>
        <h2>Great news! Your order has been delivered.</h2>
        <p>Order <strong>${order._id}</strong> was delivered successfully.</p>
        <p>We hope you enjoy your purchase! If you have any feedback, please let us know.</p>
        
        <a href="http://localhost:5173/orders/${order._id}/review" style="${buttonStyle}">Rate Your Experience</a>
        
        <div style="${footerStyle}">
          <p>&copy; 2026 SwiftCart Inc. All rights reserved.</p>
        </div>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Delivery confirmation email sent to ${recipient}`);
  } catch (error) {
    console.error('Error sending delivery confirmation email:', error);
  }
};

// 5. Refund Confirmation (User)
export const sendRefundConfirmationEmail = async (user, payment, order) => {
  const mailOptions = {
    from: process.env.ADMIN_EMAIL,
    to: user.email,
    subject: `Refund Processed - ${order._id}`,
    html: `
      <div style="${commonStyle}">
        <div style="${headerStyle}; background-color: #6366f1;">
          <h1>SwiftCart</h1>
          <p>Refund Confirmation</p>
        </div>
        <h2>Your refund has been processed!</h2>
        <p>We've processed a refund of <strong>${formatCurrency(payment.amount)}</strong> for order <strong>${order._id}</strong>.</p>
        <p>The amount has been credited back to your original payment method: <strong>${payment.method}</strong>.</p>
        <p><strong>Transaction ID:</strong> ${payment.transactionId}</p>
        
        <div style="${footerStyle}">
          <p>&copy; 2026 SwiftCart Inc. All rights reserved.</p>
        </div>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Refund confirmation email sent to ${user.email}`);
  } catch (error) {
    console.error('Error sending refund confirmation email:', error);
  }
};
