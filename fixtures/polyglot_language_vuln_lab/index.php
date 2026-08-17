<?php
Route::get('/search', function (Request $request) {
    $q = $request->query('q');
    return DB::select("SELECT * FROM products WHERE name = '" . $q . "'");
});
