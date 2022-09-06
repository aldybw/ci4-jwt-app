<?php

namespace App\Controllers;

use App\Models\UserModel;
use CodeIgniter\API\ResponseTrait;
use CodeIgniter\RESTful\ResourceController;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Login extends ResourceController
{
    /**
     * Return an array of resource objects, themselves in array format
     *
     * @return mixed
     */
    use ResponseTrait;
    public function index()
    {
        helper(['form']);
        $rules = [
            'email' => 'required|valid_email',
            'password' => 'required|min_length[6]',
        ];
        if (!$this->validate($rules)) return $this->fail($this->validator->getErrors());
        $model = new UserModel();
        $user = $model->where('email', $this->request->getVar('email'))->first();
        if (!$user) return $this->failNotFound('Email tidak ditemukan');

        $is_password_verified = password_verify($this->request->getVar('password'), $user['password']);
        if (!$is_password_verified) return $this->fail('Password salah');

        $key = getenv('TOKEN_SECRET');
        $payload = [
            'iat' => 1356999524,
            'nbf' => 1357000000,
            'uid' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            'password' => $user['password']
        ];

        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        return $this->respond($jwt);
    }
}
