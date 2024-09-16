import bcrypt from 'bcrypt';
// import bcrypt from 'bcrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';
import httpStatus from 'http-status';
import AppError from '../../errors/AppError';
import { User } from '../user/user.model';
import { TLoginUser } from './auth.interface';
import config from '../../config';

const loginUser = async (payload: TLoginUser) => {
  // checking if the user exist---------
  const user = await User.isUserExistsByCustomId(payload.id);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found!');
  }

  //  checking if the user is already deleted----------
  const isDeleted = user?.isDeleted;
  //   console.log('deleted //', isDeleted);
  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted!');
  }

  //  checking if the user is blocked----------
  const userStatus = user?.status;
  //   console.log('status //', userStatus);
  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked!');
  }

  // checking if the password correct
  if (!(await User.isPasswordMatched(payload?.password, user?.password))) {
    throw new AppError(httpStatus.FORBIDDEN, 'Password dost match!');
  }

  // Access Granted: Send AccessToken, RefreshToken
  // create token
  const jwtPayload = {
    userId: user.id,
    role: user.role,
  };

  // access token
  const accessToken = jwt.sign(jwtPayload, config.jwt_access_secret as string, {
    expiresIn: '10d',
  });

  // todo: ----------------------- video 12  time 8:37s
  // refresh token
  // const refreshToken = jwt.sign(jwtPayload, config.jwt_access_secret as string, {
  //   expiresIn: '10d',
  // });

  return { accessToken, needsPasswordChange: user?.needsPasswordChange };
};

const changePassword = async (
  userData: JwtPayload,
  payload: { oldPassword: string; newPassword: string },
) => {
  // checking if the user exist---------
  const user = await User.isUserExistsByCustomId(userData.userId);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found!');
  }

  //  checking if the user is already deleted----------
  const isDeleted = user?.isDeleted;
  //   console.log('deleted //', isDeleted);
  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted!');
  }

  //  checking if the user is blocked----------
  const userStatus = user?.status;
  //   console.log('status //', userStatus);
  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked!');
  }

  // checking if the password correct
  if (!(await User.isPasswordMatched(payload?.oldPassword, user?.password)))
    throw new AppError(httpStatus.FORBIDDEN, 'Password dost match!');

  // hash new password
  const newHashedPassword = await bcrypt.hash(
    payload.newPassword,
    Number(config.bcrypt_salt_rounds),
  );

  await User.findOneAndUpdate(
    {
      id: userData.userId,
      role: userData.role,
    },
    {
      password: newHashedPassword,
      needsPasswordChange: false,
      passwordChangedAt: new Date(),
    },
  );
  return null;
};

export const AuthService = {
  changePassword,
  loginUser,
};
