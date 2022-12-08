import sendGridMail from '@sendgrid/mail';
import config from 'config';

sendGridMail.setApiKey(config.get<string>('sendgridApiKey'));

function getMessage({ email, subject, body }: { email: string; subject: string; body: string }) {
  return {
    to: `${email}`,
    from: { email: 'thaihothanhlong95@gmail.com', name: 'Job Portal' },
    subject: `${subject}`,
    text: 'Testing',
    html: `<strong>${body}</strong>`,
  };
}
export default async function sendMail(emailTo: string, subjectEmail: string, body:string) {
  sendGridMail
    .send(getMessage({ email: emailTo, subject: subjectEmail, body }))
    .then(() => {
      console.log(`Sending to email: ${emailTo} with subject ${subjectEmail}`);
    })
    .catch((error) => {
      console.error(error);
    });
}
