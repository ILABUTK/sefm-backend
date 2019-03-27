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
        DB::table('users')->insert([
          'name' => 'Ingrid Laerdal',
          'email' => 'Ingrid.Laerdal@laerdal.com',
          'password' => bcrypt('sefm4Laerdal!'),
      	]);

        DB::table('users')->insert([
          'name' => 'Cansu Akarsu',
          'email' => 'Cansu.Akarsu@laerdal.com',
          'password' => bcrypt('sefm4Akarsu!'),
        ]);
        
        ### added outside using postman
        ### utksimulation@gmail.com, sefm@UTK2019!
    }
}
