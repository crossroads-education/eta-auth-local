import * as orm from "typeorm";
import * as eta from "../eta";
import User from "../../cre-db-shared/models/User";

@orm.Index(["person"], { unique: true })
@orm.Entity()
export default class Account {
    @orm.PrimaryGeneratedColumn()
    public id: number;

    @orm.JoinColumn()
    @orm.OneToOne(t => User, { nullable: false })
    public user: User;

    @orm.Column({ type: "varchar", nullable: false })
    public password: string;

    @orm.Column({ type: "varchar", nullable: false })
    public salt: string;

    // stop-generate
    public verifyPassword(password: string): boolean {
        const hash: string = eta.crypto.hashPassword(password, this.salt);
        return hash === password;
    }
}
