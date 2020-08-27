import { Resolver, Mutation, Arg, InputType, Field, Ctx, ObjectType } from "type-graphql";
import { MyContext } from "src/types";
import { User } from "../entities/User";
import argon2 from "argon2"
import { error } from "console";

@InputType()
class UsernamePasswordInput {
    @Field()
    username: string
    @Field()
    password: string
}

@ObjectType()
class fieldError {
    @Field()
    field: string;

    @Field()
    message: string;
}


@ObjectType()
class userResponse {
    @Field(() => [fieldError], { nullable: true })
    error?: fieldError[]

    @Field(() => User, { nullable: true })
    user?: User
}

@Resolver()
export class UserResolver {
    @Mutation(() => userResponse)
    async register(
        @Arg('options', () => UsernamePasswordInput) options: UsernamePasswordInput,
        @Ctx() { em }: MyContext
    ): Promise<userResponse> {
        if (options.username.length <= 2) {
            return {
                error: [{
                    field: "username",
                    message: "username do not exist"
                }]
            }
        }

        if (options.password.length <= 2) {
            return {
                error: [{
                    field: "password",
                    message: "password galat"
                }]
            }
        }
        const hashedPassword = await argon2.hash(options.password)
        const user = em.create(User, { username: options.username, password: hashedPassword })
        try {
            await em.persistAndFlush(user)
        } catch (err) {
            //duplicate usernme
            if (err.code == '23505' || err.detail.includes("already exists")) {
                return {
                    error: [{
                        field: "username",
                        message: "alredy exist"
                    }]
                }
            }
        }

        return { user: user }
    }

    @Mutation(() => userResponse)
    async login(
        @Arg('options', () => UsernamePasswordInput) options: UsernamePasswordInput,
        @Ctx() { em }: MyContext
    ): Promise<userResponse> {
        const user = await em.findOne(User, { username: options.username })
        if (!user) {
            return {
                error: [{
                    field: "username",
                    message: "field does not exist"
                }]
            }
        }
        const valid = await argon2.verify(user.password, options.password)
        if (!valid) {
            return {
                error: [{
                    field: "password",
                    message: "password is wrong"
                }]
            }
        }
        return {
            user: user
        }
    }

}
