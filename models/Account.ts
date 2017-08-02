import * as orm from "typeorm";
import * as eta from "../eta";
import Person from "../../cre-db-shared/models/Person";

@orm.Index(["person"], { unique: true })
@orm.Entity()
export default class Account {
    public constructor(init: Partial<Account>) {
        Object.assign(this, init);
    }

    @orm.PrimaryGeneratedColumn()
    public id: number;

    @orm.JoinColumn()
    @orm.OneToOne(t => Person, { nullable: false })
    public person: Person;

    @orm.Column({ type: "varchar", nullable: false })
    public password: string;

    @orm.Column({ type: "varchar", nullable: false })
    public salt: string;

    public verifyPassword(password: string): boolean {
        const hash: string = eta.crypto.hashPassword(password, this.salt);
        return hash === password;
    }
}
