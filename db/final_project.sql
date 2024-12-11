-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Dec 11, 2024 at 10:22 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `another`
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `nkani_users` (
  `id` int(11) NOT NULL PRIMARY AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `salt` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `nkani_users` (`id`, `username`, `email`, `password`, `role_id`, `created_at`, `updated_at`, `salt`) VALUES
(4, 'Maxw311', 'nyimbilimaxwell9@gmail.com', 'FhFWoe1fTWWnxHM4Kyj6nc2RQTpalfPcfA7xqqfliGk=', 11, '2024-12-07 23:25:54', '2024-12-07 23:25:54', 'XZAH4Qs-P5no-qj5IFT5OQ==');

-- --------------------------------------------------------

--
-- Table structure for table `user_roles`
--

CREATE TABLE `nkani_user_roles` (
  `id` int(11) NOT NULL PRIMARY AUTO_INCREMENT,
  `role_name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user_roles`
--

INSERT INTO `nkani_user_roles` (`id`, `role_name`) VALUES
(11, 'admin'),
(12, 'regular_user');

--
-- Indexes for dumped tables
--

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
