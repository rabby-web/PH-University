// import bcrypt from 'bcrypt';
import httpStatus from 'http-status';
import AppError from '../../errors/AppError';
import { User } from '../user/user.model';
import { TLoginUser } from './auth.interface';

const loginUser = async (payload: TLoginUser) => {
  // checking if the user exist---------
  const user = await User.isUserExistsByCustomId(payload.id);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found!');
  }

  // //  checking if the user is already deleted----------
  // const isDeleted = isUserExists?.isDeleted;
  // //   console.log('deleted //', isDeleted);
  // if (isDeleted) {
  //   throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted!');
  // }

  // //  checking if the user is blocked----------
  // const userStatus = isUserExists?.status;
  // //   console.log('status //', userStatus);
  // if (userStatus === 'blocked') {
  //   throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked!');
  // }

  // checking if the password correct
  if (!(await User.isPasswordMatched(payload?.password, user?.password))) {
    throw new AppError(httpStatus.FORBIDDEN, 'Password dost match!');
  }

  // Access Granted: Send AccessToken, RefreshToken
  console.log(payload);
  return {};
};
export const AuthService = {
  loginUser,
};
