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
      to: process.env.ADMIN_EMAIL,
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
                <p><strong>Payment Method:</strong> ${order.paymentMethod.type.toUpperCase()}</p>
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
      to: process.env.ADMIN_EMAIL,
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

export const sendContactEmail = async (contactData) => {
  try {
    const transporter = createTransporter();
    
    // Send confirmation email to customer
    const customerMailOptions = {
      from: process.env.EMAIL_USER,
      to: contactData.email,
      subject: `We received your message - ${contactData.subject}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #2563eb; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9fafb; }
            .message-box { background-color: white; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #2563eb; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Thank You for Contacting Us!</h1>
            </div>
            <div class="content">
              <p>Hi ${contactData.name},</p>
              
              <p>We have received your message and appreciate you reaching out to us. Our support team will review your inquiry and get back to you as soon as possible.</p>
              
              <div class="message-box">
                <h3>Your Message Details:</h3>
                <p><strong>Subject:</strong> ${contactData.subject}</p>
                <p><strong>Received:</strong> ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}</p>
                <p><strong>Your Message:</strong></p>
                <p style="white-space: pre-wrap; background-color: #f3f4f6; padding: 10px; border-radius: 4px;">${contactData.message}</p>
              </div>
              
              <p><strong>Expected Response Time:</strong> We typically respond within 24-48 business hours.</p>
              
              <p>If your inquiry is urgent, please contact us directly:</p>
              <ul>
                <li><strong>Email:</strong> support@swiftcart.com</li>
                <li><strong>Phone:</strong> +1 (555) 123-4567</li>
                <li><strong>Hours:</strong> Monday - Friday, 9:00 AM - 6:00 PM EST</li>
              </ul>
            </div>
            <div class="footer">
              <p>© 2024 SwiftCart. All rights reserved.</p>
              <p>This is an automated email. Please do not reply to this message.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    // Send notification email to admin
    const adminMailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL,
      subject: `📧 New Contact Form Submission - ${contactData.subject}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #7c3aed; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9fafb; }
            .details-box { background-color: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .message-box { background-color: #f3f4f6; padding: 15px; border-radius: 4px; margin: 15px 0; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            .action-btn { display: inline-block; background-color: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin-top: 10px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>📧 New Contact Form Submission</h1>
            </div>
            <div class="content">
              <p>A new contact form submission has been received.</p>
              
              <div class="details-box">
                <h3>Customer Information:</h3>
                <p><strong>Name:</strong> ${contactData.name}</p>
                <p><strong>Email:</strong> <a href="mailto:${contactData.email}">${contactData.email}</a></p>
                <p><strong>Subject:</strong> ${contactData.subject}</p>
                <p><strong>Submitted:</strong> ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}</p>
              </div>
              
              <div class="details-box">
                <h3>Message:</h3>
                <div class="message-box">
                  ${contactData.message.replace(/\n/g, '<br>')}
                </div>
              </div>
              
              <p><strong>Action Required:</strong></p>
              <ul>
                <li>Review the customer's inquiry</li>
                <li>Respond to ${contactData.email} within 24-48 hours</li>
                <li>Mark as resolved once addressed</li>
              </ul>
              
              <a href="mailto:${contactData.email}?subject=Re: ${contactData.subject}" class="action-btn">Reply to Customer</a>
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

    // Send both emails
    await transporter.sendMail(customerMailOptions);
    console.log('Contact confirmation email sent to:', contactData.email);
    
    await transporter.sendMail(adminMailOptions);
    console.log('Contact notification email sent to admin');
    
    return true;
  } catch (error) {
    console.error('Error sending contact email:', error);
    return false;
  }
};

// Send delivery request email to delivery boy
export const sendDeliveryRequestEmail = async (order, deliveryBoyEmail) => {
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
        </tr>
      `;
    }).join('');

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: deliveryBoyEmail,
      subject: `🚚 New Delivery Request - Order #${order._id}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #059669; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9fafb; }
            .order-details { background-color: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .alert { background-color: #d1fae5; border-left: 4px solid #059669; padding: 15px; margin: 20px 0; border-radius: 4px; }
            table { width: 100%; border-collapse: collapse; }
            .address-box { background-color: #f3f4f6; padding: 15px; border-radius: 4px; margin: 15px 0; }
            .action-buttons { text-align: center; margin: 20px 0; }
            .btn { display: inline-block; padding: 12px 30px; margin: 0 10px; border-radius: 4px; text-decoration: none; font-weight: bold; }
            .btn-accept { background-color: #059669; color: white; }
            .btn-reject { background-color: #dc2626; color: white; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🚚 New Delivery Request</h1>
            </div>
            <div class="content">
              <div class="alert">
                <strong>You have received a new delivery request!</strong> Accept or reject this order in your dashboard.
              </div>
              
              <div class="order-details">
                <h2>Order Information</h2>
                <p><strong>Order ID:</strong> ${order._id}</p>
                <p><strong>Order Date:</strong> ${new Date(order.createdAt).toLocaleDateString()}</p>
                <p><strong>Total Amount:</strong> $${order.total.toFixed(2)}</p>
                
                <h3>Customer Information:</h3>
                <p><strong>Name:</strong> ${order.shippingAddress.name}</p>
                <p><strong>Email:</strong> ${order.shippingAddress.email}</p>
                
                <h3>Delivery Address:</h3>
                <div class="address-box">
                  ${order.shippingAddress.address}<br>
                  ${order.shippingAddress.city}, ${order.shippingAddress.state} ${order.shippingAddress.zipcode}<br>
                  ${order.shippingAddress.country}
                </div>
                
                <h3>Items to Deliver:</h3>
                <table>
                  <thead>
                    <tr style="background-color: #f3f4f6;">
                      <th style="padding: 10px; text-align: left;">Product</th>
                      <th style="padding: 10px; text-align: center;">Quantity</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${itemsList}
                  </tbody>
                </table>
              </div>
              
              <p><strong>What happens next?</strong></p>
              <ul>
                <li>If you accept, you'll be assigned to this delivery</li>
                <li>You can then update the order status as you deliver</li>
                <li>If you reject, another delivery boy can accept it</li>
              </ul>
              
              <div class="action-buttons">
                <p><strong>Respond to this request in your dashboard:</strong></p>
                <a href="http://localhost:5173/deliveryboy" class="btn btn-accept">Go to Dashboard</a>
              </div>
            </div>
            <div class="footer">
              <p>© 2024 SwiftCart. All rights reserved.</p>
              <p>This is an automated notification. Please do not reply to this email.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Delivery request email sent to:', deliveryBoyEmail);
    return true;
  } catch (error) {
    console.error('Error sending delivery request email:', error);
    return false;
  }
};
