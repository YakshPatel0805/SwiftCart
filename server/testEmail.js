import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Test email configuration
const testEmailSetup = async () => {
  console.log('Testing email configuration...\n');
  
  // Check if environment variables are set
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.error('❌ ERROR: EMAIL_USER and EMAIL_PASSWORD must be set in .env file');
    console.log('\nPlease update your .env file with:');
    console.log('EMAIL_USER=your-email@gmail.com');
    console.log('EMAIL_PASSWORD=your-app-password');
    process.exit(1);
  }
  
  console.log('✓ Environment variables found');
  console.log(`  EMAIL_USER: ${process.env.EMAIL_USER}`);
  console.log(`  EMAIL_PASSWORD: ${'*'.repeat(process.env.EMAIL_PASSWORD.length)}\n`);
  
  // Create transporter
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  
  // Verify connection
  try {
    console.log('Testing SMTP connection...');
    await transporter.verify();
    console.log('✓ SMTP connection successful\n');
  } catch (error) {
    console.error('❌ SMTP connection failed:', error.message);
    console.log('\nTroubleshooting tips:');
    console.log('1. Ensure 2-Step Verification is enabled on your Google Account');
    console.log('2. Generate an App Password at: https://myaccount.google.com/apppasswords');
    console.log('3. Use the App Password (not your regular password) in .env');
    process.exit(1);
  }
  
  // Send test email
  try {
    console.log('Sending test email...');
    const info = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER, // Send to yourself
      subject: 'SwiftCart Email Test',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { padding: 20px; background-color: #f9fafb; border-radius: 0 0 8px 8px; }
            .success { background-color: #10b981; color: white; padding: 15px; border-radius: 8px; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>✓ Email Configuration Successful!</h1>
            </div>
            <div class="content">
              <div class="success">
                <strong>Congratulations!</strong> Your email service is configured correctly.
              </div>
              <p>This is a test email from SwiftCart to verify your email configuration.</p>
              <p><strong>Email Service:</strong> Gmail</p>
              <p><strong>Sent at:</strong> ${new Date().toLocaleString()}</p>
              <p>Your application can now send:</p>
              <ul>
                <li>Order confirmation emails</li>
                <li>Payment confirmation emails</li>
                <li>Order cancellation emails</li>
              </ul>
              <p style="color: #666; font-size: 12px; margin-top: 20px;">
                This is an automated test email from SwiftCart.
              </p>
            </div>
          </div>
        </body>
        </html>
      `
    });
    
    console.log('✓ Test email sent successfully!');
    console.log(`  Message ID: ${info.messageId}`);
    console.log(`\n✓ Email configuration is working correctly!`);
    console.log(`  Check your inbox at: ${process.env.EMAIL_USER}\n`);
    
  } catch (error) {
    console.error('❌ Failed to send test email:', error.message);
    process.exit(1);
  }
};

// Run the test
testEmailSetup();
