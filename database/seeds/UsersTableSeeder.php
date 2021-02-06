<?php

use Illuminate\Database\Seeder;

class UsersTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        // DB::table('users')->insert([
        //   'name' => 'Ingrid Laerdal',
        //   'email' => 'Ingrid.Laerdal@laerdal.com',
        //   'password' => bcrypt('sefm4Laerdal!'),
      	// ]);

        // DB::table('users')->insert([
        //   'name' => 'Cansu Akarsu',
        //   'email' => 'Cansu.Akarsu@laerdal.com',
        //   'password' => bcrypt('sefm4Akarsu!'),
        // ]);
        
        /// harold.andersen@wsu.edu; sefm20194WSU!
        /// student@wsu.edu; stu20194SEFM!

        /// ### added outside using postman
        ///### utksimulation@gmail.com, sefm@UTK2019!
    
        // Xueping.Li@utk.edu secret!

        DB::table('users')->insert([
          'name' => 'XP Li',
          'email' => 'xli27@utk.edu',
          'password' => bcrypt('secret!'),
        ]);
    }
}
