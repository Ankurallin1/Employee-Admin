const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    port: 587,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        rejectUnauthorized: true,
    },
});

const sendVerificationEmail = (user,text,message) => {
    const mailOptions = {
        from: `"Ankur Srivastava" <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: 'Email Verification',
        text: `${text}`,
        html: `
            ${message}
        `,
        replyTo: process.env.EMAIL_USER,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
};

module.exports = { sendVerificationEmail };
