<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Auth;

class AuthApi extends Controller
{
    public function response($user)
    {
        $token = $user->createToken(str()->random(40))->plainTextToken;
        return response()->json([
            'user'=>$user,
            'token'=>$token,
            'token_type'=>'Bearer'
        ]);
    }

    /**
     * Create Todo
     * @OA\Post (
     *     path="/api/registre",
     *     tags={"AUTH"},
     *     @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 @OA\Property(
     *                      type="object",
     *                      @OA\Property(
     *                          property="name",
     *                          type="string"
     *                      ),
     *                      @OA\Property(
     *                          property="email",
     *                          type="string"
     *                      )
     *                 ),
     *                 example={
     *                     "title":"example title",
     *                     "content":"example content"
     *                }
     *             )
     *         )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="success",
     *          @OA\JsonContent(
     *              @OA\Property(property="id", type="number", example=1),
     *              @OA\Property(property="name", type="string", example="name"),
     *              @OA\Property(property="email", type="string", example="email"),
     *              @OA\Property(property="password", type="string", example="password"),
     *              @OA\Property(property="updated_at", type="string", example="2021-12-11T09:25:53.000000Z"),
     *              @OA\Property(property="created_at", type="string", example="2021-12-11T09:25:53.000000Z"),
     *          )
     *      ),
     *      @OA\Response(
     *          response=400,
     *          description="invalid",
     *          @OA\JsonContent(
     *              @OA\Property(property="msg", type="string", example="fail"),
     *          )
     *      )
     * )
     */


    public function register(Request $req)
    {
        $req->validate([
            'name'=>'required|min:3',
            'email'=>'required|email|unique:users',
            'password'=>'required|min:4|confirmed'
        ]);
        $user = User::create([
            'name'=>ucwords($req->name),
            'email'=>$req->email,
            'password'=> bcrypt($req->password)
        ]);
        return $this->response($user);
    }

    public function login(Request $req)
    {
        $cred = $req->validate([
            'email'=>'required|email|exists:users',
            'password'=>'required|min:4'
        ]);
        if (!Auth::attempt($cred)) {
            return response()->json([
                'message'=>'Unauthorized.'
            ],401);
        }

        return $this->response(Auth::user());
    }

    public function logout(Type $var = null)
    {
        Auth::user()->tokens()->delete();
        return response()->json([
            'message'=>'you have successfully logged out and token was succesfull deleted'
        ]);
    }
}
