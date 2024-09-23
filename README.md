Learning MongooseIM through small tasks:

- A task to check if the encrypted message (OMEMO) from User A to UserB has correct rid of UserB. 
Normally MongooseIM will stop the transaction if rid is wrong. So the task is to return Error Stanza to UserA that DeviceID is incorrect along woth stopping the transaction.

Used existing hook "user_send_message" to add a new custom handler module called custon_verify_resource where the logic to check rid is present.

Used Cets and Mysql for trasient and persistent backend. 

