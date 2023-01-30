import { IsNotEmpty, MaxLength, MinLength } from 'class-validator';

export class resetPassword {
  @IsNotEmpty({ message: 'The password must not be empty' })
  @MinLength(8)
  @MaxLength(64)
  newPassword: string;
}
