import cron from 'node-cron';
import User from '../models/user_model.js';

export const setUserCleanupTask = () => {
    cron.schedule('*/5 * * * * ', async ()=>{
        console.log('running cleanup task');
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000); // 5 minutes ago
        try {
            const result = await  User.deleteMany({
                isPhoneVerified: false,
                createdAt: {$lt : fiveMinutesAgo}
            });
            console.log(` Unverified users  ${result.deletedCount} Deleted from the database`);
        } catch (error){
            console.error('Error cleaning ip unverified users:', error)
        }
    });
};
export default setUserCleanupTask;