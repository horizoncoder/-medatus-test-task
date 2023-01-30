import { IsEmail, IsNotEmpty, MaxLength, MinLength } from 'class-validator';

export class RegisterDto {
  @IsNotEmpty({ message: 'You must enter an email in the username field' })
  @IsEmail()
  @MaxLength(254)
  username: string;

  @IsNotEmpty({ message: 'The password must not be empty' })
  @MinLength(8)
  @MaxLength(64)
  password: string;
}
