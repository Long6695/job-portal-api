import sendGridMail from '@sendgrid/mail';
import config from 'config';

sendGridMail.setApiKey(config.get<string>('sendgridApiKey'));

function getMessage({ email, subject, url, templateId }: { email: string; subject: string; url: string, templateId: string }) {
  return {
    to: `${email}`,
    from: { email: 'thaihothanhlong95@gmail.com', name: 'Job Portal' },
    subject: `${subject}`,
    templateId: `${templateId}`,
    dynamicTemplateData: {
      name: `${email.split('@')[0]}`,
      url: url,
    },
  };
}
export default async function sendMail(emailTo: string, subjectEmail: string, url:string, templateId: string) {
  sendGridMail
    .send(getMessage({ email: emailTo, subject: subjectEmail, url, templateId }))
    .then(() => {
      console.log(`Sending to email: ${emailTo} with subject ${subjectEmail}`);
    })
    .catch((error) => {
      console.error(error);
    });
}
